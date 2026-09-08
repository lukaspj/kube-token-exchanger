// Package controller implements the TokenExchangeRequest reconciliation loop.
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/laldershaab/kube-token-exchanger/api/v1alpha1"
	"github.com/laldershaab/kube-token-exchanger/internal/authentik"
	"github.com/laldershaab/kube-token-exchanger/internal/metrics"
)

const (
	// SecretKeyToken is the Secret key holding the authentik access token.
	SecretKeyToken = "token"
	// SecretKeyExpiresAt is the Secret key holding the RFC3339 expiry time.
	SecretKeyExpiresAt = "expiresAt"
	// SecretKeyScope is the Secret key holding the granted scope.
	SecretKeyScope = "scope"
	// SecretKeyIssuedTokenType is the Secret key holding the issued token type.
	SecretKeyIssuedTokenType = "issuedTokenType"
	// SecretKeyAudience is the Secret key holding the Kubernetes audience.
	SecretKeyAudience = "audience"
	// SecretKeyServiceAccount is the Secret key holding the ServiceAccount name.
	SecretKeyServiceAccount = "serviceAccount"
	// SecretKeyServiceAccountNamespace is the Secret key holding the ServiceAccount namespace.
	SecretKeyServiceAccountNamespace = "serviceAccountNamespace"

	// ConditionReady indicates the exchange status.
	ConditionReady = "Ready"

	// ReasonInvalidSpec marks an unusable spec.
	ReasonInvalidSpec = "InvalidSpec"
	// ReasonTokenIssued marks a successful exchange.
	ReasonTokenIssued = "TokenIssued"
	// ReasonExchangeFailed marks a failed exchange.
	ReasonExchangeFailed = "ExchangeFailed"

	defaultTokenLifetime = 5 * time.Minute
	defaultRefreshWindow = 30 * time.Second
	// assertionLifetime bounds the lifetime of the minted client_assertion
	// JWT used with private_key_jwt client authentication.
	assertionLifetime = 2 * time.Minute
)

// Minter mints bound Kubernetes ServiceAccount tokens.
type Minter interface {
	Mint(ctx context.Context, namespace, name string, audiences []string, lifetime time.Duration) (string, error)
}

// Exchanger exchanges a subject token for an authentik identity token.
type Exchanger interface {
	Exchange(ctx context.Context, req authentik.ExchangeRequest) (*authentik.ExchangeResponse, error)
}

// AuthentikClientFunc builds an authentik client from resolved configuration.
type AuthentikClientFunc func(ctx context.Context, cfg authentik.Config) (Exchanger, error)

// TokenExchangeRequestReconciler reconciles TokenExchangeRequest objects.
type TokenExchangeRequestReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Minter   Minter
	// NewAuthentikClient is a factory returning an Exchanger for the given
	// configuration. Defaults to building an *authentik.Client.
	NewAuthentikClient AuthentikClientFunc
}

// +kubebuilder:rbac:groups=tokenexchange.aldershaab-it.dk,resources=tokenexchangerequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tokenexchange.aldershaab-it.dk,resources=tokenexchangerequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tokenexchange.aldershaab-it.dk,resources=tokenexchangerequests/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

// Reconcile implements the main loop for TokenExchangeRequest resources.
func (r *TokenExchangeRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var ter v1alpha1.TokenExchangeRequest
	if err := r.Get(ctx, req.NamespacedName, &ter); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	now := time.Now()

	// Drop the TTL gauge for CRs that are gone.
	defer func() {
		if !ter.DeletionTimestamp.IsZero() {
			metrics.TokenTTLSeconds.DeleteLabelValues(ter.Namespace, ter.Name)
		}
	}()

	saNamespace := namespaceOrDefault(ter.Namespace, ter.Spec.ServiceAccount.Namespace)
	secretNamespace := namespaceOrDefault(ter.Namespace, ter.Spec.TargetSecret.Namespace)
	refreshWindow := durationOrDefault(ter.Spec.RefreshWindow, defaultRefreshWindow)

	// A fresh token already exists: nothing to do but wait.
	fresh, expiresAt, err := r.tokenIsFresh(ctx, secretNamespace, ter.Spec.TargetSecret.Name, now, refreshWindow)
	if err != nil {
		return ctrl.Result{}, err
	}
	if fresh {
		ttl := time.Until(expiresAt)
		metrics.TokenTTLSeconds.WithLabelValues(ter.Namespace, ter.Name).Set(ttl.Seconds())
		requeueAfter := ttl - refreshWindow
		if requeueAfter <= 0 {
			requeueAfter = time.Second
		}
		log.V(1).Info("token still fresh, waiting", "expiresAt", expiresAt, "requeueAfter", requeueAfter)
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	if err := validateSpec(&ter); err != nil {
		r.markFailed(ctx, &ter, ReasonInvalidSpec, err.Error())
		r.Recorder.Event(&ter, corev1.EventTypeWarning, ReasonInvalidSpec, err.Error())
		return ctrl.Result{}, nil
	}

	cfg, err := r.authentikConfig(ctx, &ter)
	if err != nil {
		r.markFailed(ctx, &ter, ReasonInvalidSpec, err.Error())
		r.Recorder.Event(&ter, corev1.EventTypeWarning, ReasonInvalidSpec, err.Error())
		return ctrl.Result{}, nil
	}

	exchanger, err := r.exchanger(ctx, cfg)
	if err != nil {
		return ctrl.Result{}, err
	}

	lifetime := durationOrDefault(ter.Spec.TokenLifetime, defaultTokenLifetime)

	saToken, err := r.Minter.Mint(ctx, saNamespace, ter.Spec.ServiceAccount.Name, []string{ter.Spec.Audience}, lifetime)
	if err != nil {
		return r.failExchange(ctx, &ter, fmt.Errorf("minting ServiceAccount token: %w", err))
	}

	start := time.Now()
	exchangeReq := authentik.ExchangeRequest{
		SubjectToken: saToken,
		Scopes:       ter.Spec.Authentik.Scopes,
	}

	if cfg.ClientAuthMethod == authentik.ClientAuthPrivateKeyJWT {
		assertion, err := r.mintClientAssertion(ctx, &ter, cfg)
		if err != nil {
			return r.failExchange(ctx, &ter, fmt.Errorf("minting client assertion: %w", err))
		}
		exchangeReq.ClientAssertion = assertion
	}

	resp, err := exchanger.Exchange(ctx, exchangeReq)
	metrics.ExchangeDurationSeconds.WithLabelValues(ter.Namespace, ter.Name).Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.ExchangesTotal.WithLabelValues(ter.Namespace, ter.Name, "error").Inc()
		return r.failExchange(ctx, &ter, err)
	}
	metrics.ExchangesTotal.WithLabelValues(ter.Namespace, ter.Name, "success").Inc()

	expiry := resp.Expiry(now)
	if err := r.writeSecret(ctx, &ter, secretNamespace, resp, expiry, saNamespace); err != nil {
		return ctrl.Result{}, err
	}

	meta.SetStatusCondition(&ter.Status.Conditions, metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonTokenIssued,
		Message:            fmt.Sprintf("token issued, expires %s", expiry.Format(time.RFC3339)),
		ObservedGeneration: ter.Generation,
		LastTransitionTime: metav1.NewTime(now),
	})
	ter.Status.LastExchangeTime = &metav1.Time{Time: now}
	ter.Status.TokenExpiresAt = &metav1.Time{Time: expiry}
	ter.Status.IssuedTokenType = resp.IssuedTokenType
	ter.Status.Scope = resp.Scope
	if err := r.Status().Update(ctx, &ter); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	metrics.TokenTTLSeconds.WithLabelValues(ter.Namespace, ter.Name).Set(time.Until(expiry).Seconds())
	r.Recorder.Eventf(&ter, corev1.EventTypeNormal, ReasonTokenIssued,
		"issued authentik token for ServiceAccount %s/%s, expires %s",
		saNamespace, ter.Spec.ServiceAccount.Name, expiry.Format(time.RFC3339))

	requeueAfter := time.Until(expiry) - refreshWindow
	if requeueAfter <= 0 {
		requeueAfter = time.Second
	}
	log.Info("token exchanged", "serviceAccount", ter.Spec.ServiceAccount.Name, "expiresAt", expiry, "requeueAfter", requeueAfter)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *TokenExchangeRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TokenExchangeRequest{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *TokenExchangeRequestReconciler) tokenIsFresh(ctx context.Context, namespace, name string, now time.Time, refreshWindow time.Duration) (bool, time.Time, error) {
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}
	raw, ok := sec.Data[SecretKeyExpiresAt]
	if !ok {
		return false, time.Time{}, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, string(raw))
	if err != nil {
		return false, time.Time{}, nil
	}
	return expiresAt.After(now.Add(refreshWindow)), expiresAt, nil
}

func (r *TokenExchangeRequestReconciler) authentikConfig(ctx context.Context, ter *v1alpha1.TokenExchangeRequest) (authentik.Config, error) {
	cfg := authentik.Config{
		URL:              ter.Spec.Authentik.URL,
		TokenPath:        ter.Spec.Authentik.TokenEndpointPath,
		ClientAuthMethod: ter.Spec.Authentik.ClientAuthMethod,
		InsecureTLS:      ter.Spec.Authentik.InsecureTLS,
		Timeout:          durationOrDefault(ter.Spec.Authentik.Timeout, 15*time.Second),
	}

	clientID, err := r.secretValue(ctx, ter, ter.Spec.Authentik.ClientID)
	if err != nil {
		return cfg, err
	}
	cfg.ClientID = clientID

	if cfg.ClientAuthMethod != authentik.ClientAuthPrivateKeyJWT {
		clientSecret, err := r.secretValue(ctx, ter, ter.Spec.Authentik.ClientSecret)
		if err != nil {
			return cfg, err
		}
		cfg.ClientSecret = clientSecret
	}

	if ter.Spec.Authentik.CACert != nil {
		ca, err := r.secretValue(ctx, ter, *ter.Spec.Authentik.CACert)
		if err != nil {
			return cfg, err
		}
		cfg.CACert = []byte(ca)
	}
	return cfg, nil
}

func (r *TokenExchangeRequestReconciler) secretValue(ctx context.Context, ter *v1alpha1.TokenExchangeRequest, sel v1alpha1.SecretKeySelector) (string, error) {
	ns := namespaceOrDefault(ter.Namespace, sel.Namespace)
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: sel.Name}, &sec); err != nil {
		return "", fmt.Errorf("reading secret %s/%s: %w", ns, sel.Name, err)
	}
	val, ok := sec.Data[sel.Key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s has no key %q", ns, sel.Name, sel.Key)
	}
	return string(val), nil
}

// mintClientAssertion mints the bound ServiceAccount token presented as the
// client_assertion for private_key_jwt client authentication. The audience
// defaults to the resolved OAuth2 client ID.
func (r *TokenExchangeRequestReconciler) mintClientAssertion(ctx context.Context, ter *v1alpha1.TokenExchangeRequest, cfg authentik.Config) (string, error) {
	sa := ter.Spec.Authentik.ClientAssertionServiceAccount
	audience := ter.Spec.Authentik.ClientAssertionAudience
	if audience == "" {
		audience = cfg.ClientID
	}
	return r.Minter.Mint(ctx, namespaceOrDefault(ter.Namespace, sa.Namespace), sa.Name, []string{audience}, assertionLifetime)
}

func (r *TokenExchangeRequestReconciler) exchanger(ctx context.Context, cfg authentik.Config) (Exchanger, error) {	if r.NewAuthentikClient != nil {
		return r.NewAuthentikClient(ctx, cfg)
	}
	return authentik.New(cfg)
}

func (r *TokenExchangeRequestReconciler) writeSecret(ctx context.Context, ter *v1alpha1.TokenExchangeRequest, namespace string, resp *authentik.ExchangeResponse, expiry time.Time, saNamespace string) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ter.Spec.TargetSecret.Name,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(ter, v1alpha1.GroupVersion.WithKind("TokenExchangeRequest")),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			SecretKeyToken:                  []byte(resp.AccessToken),
			SecretKeyExpiresAt:              []byte(expiry.Format(time.RFC3339)),
			SecretKeyScope:                  []byte(resp.Scope),
			SecretKeyIssuedTokenType:        []byte(resp.IssuedTokenType),
			SecretKeyAudience:               []byte(ter.Spec.Audience),
			SecretKeyServiceAccount:         []byte(ter.Spec.ServiceAccount.Name),
			SecretKeyServiceAccountNamespace: []byte(saNamespace),
		},
	}

	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ter.Spec.TargetSecret.Name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		return r.Create(ctx, sec)
	case err != nil:
		return fmt.Errorf("reading target secret: %w", err)
	default:
		existing.Data = sec.Data
		existing.OwnerReferences = sec.OwnerReferences
		return r.Update(ctx, &existing)
	}
}

func (r *TokenExchangeRequestReconciler) markFailed(ctx context.Context, ter *v1alpha1.TokenExchangeRequest, reason, message string) {
	meta.SetStatusCondition(&ter.Status.Conditions, metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ter.Generation,
		LastTransitionTime: metav1.Now(),
	})
	if err := r.Status().Update(ctx, ter); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "updating failure condition")
	}
}

func (r *TokenExchangeRequestReconciler) failExchange(ctx context.Context, ter *v1alpha1.TokenExchangeRequest, err error) (ctrl.Result, error) {
	r.markFailed(ctx, ter, ReasonExchangeFailed, err.Error())
	r.Recorder.Event(ter, corev1.EventTypeWarning, ReasonExchangeFailed, err.Error())
	// Returning the error makes controller-runtime apply exponential backoff.
	return ctrl.Result{}, err
}

func validateSpec(ter *v1alpha1.TokenExchangeRequest) error {
	if ter.Spec.Audience == "" {
		return fmt.Errorf("spec.audience is required")
	}
	if ter.Spec.ServiceAccount.Name == "" {
		return fmt.Errorf("spec.serviceAccount.name is required")
	}
	if ter.Spec.Authentik.URL == "" {
		return fmt.Errorf("spec.authentik.url is required")
	}
	switch ter.Spec.Authentik.ClientAuthMethod {
	case "", authentik.ClientAuthClientSecretPost:
	case authentik.ClientAuthPrivateKeyJWT:
		if ter.Spec.Authentik.ClientAssertionServiceAccount == nil || ter.Spec.Authentik.ClientAssertionServiceAccount.Name == "" {
			return fmt.Errorf("spec.authentik.clientAssertionServiceAccount.name is required when clientAuthMethod is privateKeyJwt")
		}
	default:
		return fmt.Errorf("spec.authentik.clientAuthMethod %q is unsupported", ter.Spec.Authentik.ClientAuthMethod)
	}
	if ter.Spec.TargetSecret.Name == "" {
		return fmt.Errorf("spec.targetSecret.name is required")
	}
	return nil
}

func namespaceOrDefault(primary, fallback string) string {
	if fallback != "" {
		return fallback
	}
	return primary
}

func durationOrDefault(d *metav1.Duration, def time.Duration) time.Duration {
	if d == nil || d.Duration <= 0 {
		return def
	}
	return d.Duration
}
