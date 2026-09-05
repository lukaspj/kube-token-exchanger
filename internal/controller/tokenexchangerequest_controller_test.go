package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/laldershaab/kube-token-exchanger/api/v1alpha1"
	"github.com/laldershaab/kube-token-exchanger/internal/authentik"
)

type fakeMinter struct {
	calls int
	err   error
}

func (m *fakeMinter) Mint(_ context.Context, namespace, name string, audiences []string, lifetime time.Duration) (string, error) {
	m.calls++
	if m.err != nil {
		return "", m.err
	}
	return "k8s-sa-token", nil
}

type fakeExchanger struct {
	calls int
	resp  *authentik.ExchangeResponse
	err   error
}

func (e *fakeExchanger) Exchange(_ context.Context, req authentik.ExchangeRequest) (*authentik.ExchangeResponse, error) {
	e.calls++
	if e.err != nil {
		return nil, e.err
	}
	return e.resp, nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func testCR(name, namespace string) *v1alpha1.TokenExchangeRequest {
	return &v1alpha1.TokenExchangeRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "tokenexchange.aldershaab-it.dk/v1alpha1",
			Kind:       "TokenExchangeRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid"),
		},
		Spec: v1alpha1.TokenExchangeRequestSpec{
			ServiceAccount: v1alpha1.ServiceAccountRef{Name: "sa", Namespace: namespace},
			Audience:       "test-audience",
			Authentik: v1alpha1.AuthentikConfig{
				URL:          "https://authentik.example.com",
				ClientID:     v1alpha1.SecretKeySelector{Name: "auth", Key: "id"},
				ClientSecret: v1alpha1.SecretKeySelector{Name: "auth", Key: "secret"},
				Scopes:       []string{"openid"},
			},
			TargetSecret: v1alpha1.SecretRef{Name: "target", Namespace: namespace},
		},
	}
}

func clientSecret(namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: namespace},
		Data: map[string][]byte{
			"id":     []byte("client-id"),
			"secret": []byte("client-secret"),
		},
	}
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*TokenExchangeRequestReconciler, client.Client, *fakeMinter, *fakeExchanger) {
	t.Helper()
	s := testScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&v1alpha1.TokenExchangeRequest{}).
		WithObjects(objs...).
		Build()

	minter := &fakeMinter{}
	exchanger := &fakeExchanger{
		resp: &authentik.ExchangeResponse{
			AccessToken:     "authentik-token",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			Scope:           "openid",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		},
	}

	r := &TokenExchangeRequestReconciler{
		Client:   c,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(32),
		Minter:   minter,
		NewAuthentikClient: func(_ context.Context, _ authentik.Config) (Exchanger, error) {
			return exchanger, nil
		},
	}
	return r, c, minter, exchanger
}

func TestReconcileIssuesToken(t *testing.T) {
	r, c, minter, exchanger := newTestReconciler(t, testCR("t1", "ns1"), clientSecret("ns1"))

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > time.Hour {
		t.Errorf("RequeueAfter = %v, want in (0, 1h]", res.RequeueAfter)
	}
	if minter.calls != 1 || exchanger.calls != 1 {
		t.Errorf("minter=%d exchanger=%d, want 1 each", minter.calls, exchanger.calls)
	}

	sec := &corev1.Secret{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "target"}, sec); err != nil {
		t.Fatalf("getting secret: %v", err)
	}
	if string(sec.Data[SecretKeyToken]) != "authentik-token" {
		t.Errorf("secret token = %q", sec.Data[SecretKeyToken])
	}
	if string(sec.Data[SecretKeyAudience]) != "test-audience" {
		t.Errorf("secret audience = %q", sec.Data[SecretKeyAudience])
	}
	if _, err := time.Parse(time.RFC3339, string(sec.Data[SecretKeyExpiresAt])); err != nil {
		t.Errorf("invalid expiresAt %q: %v", sec.Data[SecretKeyExpiresAt], err)
	}
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].Kind != "TokenExchangeRequest" {
		t.Errorf("owner refs = %+v", sec.OwnerReferences)
	}

	ter := &v1alpha1.TokenExchangeRequest{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "t1"}, ter); err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	cond := meta.FindStatusCondition(ter.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != ReasonTokenIssued {
		t.Errorf("condition = %+v", cond)
	}
	if ter.Status.LastExchangeTime == nil || ter.Status.TokenExpiresAt == nil {
		t.Errorf("status times not set: %+v", ter.Status)
	}
}

func TestReconcileSkipsWhenFresh(t *testing.T) {
	cr := testCR("t1", "ns1")
	expiry := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "ns1"},
		Data: map[string][]byte{
			SecretKeyToken:     []byte("existing"),
			SecretKeyExpiresAt: []byte(expiry),
		},
	}

	r, _, minter, exchanger := newTestReconciler(t, cr, clientSecret("ns1"), existing)

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if minter.calls != 0 || exchanger.calls != 0 {
		t.Errorf("expected no exchange, got minter=%d exchanger=%d", minter.calls, exchanger.calls)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected requeue, got %v", res.RequeueAfter)
	}
}

func TestReconcileRotatesExpired(t *testing.T) {
	cr := testCR("t1", "ns1")
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "ns1"},
		Data: map[string][]byte{
			SecretKeyToken:     []byte("stale"),
			SecretKeyExpiresAt: []byte(time.Now().Add(-time.Minute).Format(time.RFC3339)),
		},
	}

	r, c, minter, exchanger := newTestReconciler(t, cr, clientSecret("ns1"), existing)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if minter.calls != 1 || exchanger.calls != 1 {
		t.Errorf("minter=%d exchanger=%d, want 1 each", minter.calls, exchanger.calls)
	}

	sec := &corev1.Secret{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "target"}, sec); err != nil {
		t.Fatalf("getting secret: %v", err)
	}
	if string(sec.Data[SecretKeyToken]) != "authentik-token" {
		t.Errorf("secret token = %q, want rotated token", sec.Data[SecretKeyToken])
	}
}

func TestReconcileExchangeFailure(t *testing.T) {
	r, c, _, exchanger := newTestReconciler(t, testCR("t1", "ns1"), clientSecret("ns1"))
	exchanger.err = errors.New("authentik: token exchange rejected: invalid_grant")

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}}); err == nil {
		t.Fatal("expected error")
	}

	ter := &v1alpha1.TokenExchangeRequest{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "t1"}, ter); err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	cond := meta.FindStatusCondition(ter.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != ReasonExchangeFailed {
		t.Errorf("condition = %+v", cond)
	}
}

func TestReconcileInvalidSpec(t *testing.T) {
	cr := testCR("t1", "ns1")
	cr.Spec.Audience = ""

	r, c, _, _ := newTestReconciler(t, cr, clientSecret("ns1"))

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.Requeue {
		t.Error("expected no requeue for invalid spec")
	}

	ter := &v1alpha1.TokenExchangeRequest{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "t1"}, ter); err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	cond := meta.FindStatusCondition(ter.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != ReasonInvalidSpec {
		t.Errorf("condition = %+v", cond)
	}
}

func TestReconcileMissingClientSecret(t *testing.T) {
	r, c, _, exchanger := newTestReconciler(t, testCR("t1", "ns1"))

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.Requeue {
		t.Error("expected no requeue")
	}
	if exchanger.calls != 0 {
		t.Error("exchange attempted despite missing secret")
	}

	ter := &v1alpha1.TokenExchangeRequest{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "t1"}, ter); err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	cond := meta.FindStatusCondition(ter.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != ReasonInvalidSpec {
		t.Errorf("condition = %+v", cond)
	}
}

func TestReconcileMintFailure(t *testing.T) {
	r, _, _, _ := newTestReconciler(t, testCR("t1", "ns1"), clientSecret("ns1"))
	r.Minter = &fakeMinter{err: errors.New("forbidden")}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "t1"}}); err == nil {
		t.Fatal("expected error")
	}
}

func TestReconcileNotFound(t *testing.T) {
	r, _, _, _ := newTestReconciler(t)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "gone"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}
