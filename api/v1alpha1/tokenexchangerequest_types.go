package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TokenExchangeRequestSpec defines the desired state of TokenExchangeRequest.
type TokenExchangeRequestSpec struct {
	// ServiceAccount identifies the Kubernetes ServiceAccount whose identity
	// token is exchanged for an authentik identity token.
	ServiceAccount ServiceAccountRef `json:"serviceAccount"`

	// Audience is the bound audience requested for the minted Kubernetes
	// ServiceAccount token. It must match the audience configuration of the
	// OIDC source registered in authentik.
	Audience string `json:"audience"`

	// TokenLifetime is the requested lifetime of the minted Kubernetes
	// ServiceAccount token. Defaults to 5m.
	// +optional
	TokenLifetime *metav1.Duration `json:"tokenLifetime,omitempty"`

	// RefreshWindow defines how long before expiry a new exchange is
	// triggered. Defaults to 30s.
	// +optional
	RefreshWindow *metav1.Duration `json:"refreshWindow,omitempty"`

	// Authentik holds the connection settings for the authentik token
	// endpoint performing the RFC 8693 token exchange.
	Authentik AuthentikConfig `json:"authentik"`

	// TargetSecret is the Secret the exchanged authentik token is written to.
	TargetSecret SecretRef `json:"targetSecret"`
}

// ServiceAccountRef references a Kubernetes ServiceAccount.
type ServiceAccountRef struct {
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// SecretRef references a Kubernetes Secret. When Namespace is empty, the
// namespace of the TokenExchangeRequest is used.
type SecretRef struct {
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// AuthentikConfig holds the connection settings for the authentik instance.
type AuthentikConfig struct {
	// URL is the base URL of the authentik instance, e.g.
	// https://authentik.example.com.
	URL string `json:"url"`

	// ClientID references the OAuth2 client_id used for the exchange.
	ClientID SecretKeySelector `json:"clientId"`

	// ClientSecret references the OAuth2 client_secret used for the exchange.
	// Ignored when clientAuthMethod is privateKeyJwt.
	ClientSecret SecretKeySelector `json:"clientSecret"`

	// ClientAuthMethod selects how the operator authenticates itself to
	// authentik.
	//
	// "clientSecretPost" (default) sends the OAuth2 client_secret in the
	// token request body.
	//
	// "privateKeyJwt" presents a freshly minted Kubernetes ServiceAccount
	// token as a client_assertion (JWT bearer, RFC 7523) signed by the
	// Kubernetes API server. authentik must trust the Kubernetes API
	// server's JWKS. No client_secret is required.
	// +optional
	// +kubebuilder:validation:Enum=clientSecretPost;privateKeyJwt
	// +kubebuilder:default:=clientSecretPost
	ClientAuthMethod string `json:"clientAuthMethod,omitempty"`

	// ClientAssertionServiceAccount is the ServiceAccount whose bound token
	// is presented as the client_assertion when clientAuthMethod is
	// privateKeyJwt. Required in that mode. When Namespace is empty, the
	// namespace of the TokenExchangeRequest is used.
	// +optional
	ClientAssertionServiceAccount *ServiceAccountRef `json:"clientAssertionServiceAccount,omitempty"`

	// ClientAssertionAudience is the audience requested for the client
	// assertion token. Defaults to the resolved OAuth2 client ID.
	// +optional
	ClientAssertionAudience string `json:"clientAssertionAudience,omitempty"`

	// Scopes requested on the exchanged token, e.g. openid, email.
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// TokenEndpointPath overrides the token endpoint path.
	// Defaults to /application/o/token/.
	// +optional
	TokenEndpointPath string `json:"tokenEndpointPath,omitempty"`

	// Timeout for HTTP requests against authentik. Defaults to 15s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// InsecureTLS disables TLS certificate verification. Do not enable in
	// production.
	// +optional
	InsecureTLS bool `json:"insecureTLS,omitempty"`

	// CACert references a PEM certificate authority used to verify the
	// authentik TLS certificate.
	// +optional
	CACert *SecretKeySelector `json:"caCert,omitempty"`
}

// SecretKeySelector references a key in a Secret. When Namespace is empty,
// the namespace of the TokenExchangeRequest is used.
type SecretKeySelector struct {
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
	Key      string `json:"key"`
}

// TokenExchangeRequestStatus defines the observed state of TokenExchangeRequest.
type TokenExchangeRequestStatus struct {
	// Conditions represent the latest available observations of the exchange.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// LastExchangeTime is the last time an exchange succeeded.
	// +optional
	LastExchangeTime *metav1.Time `json:"lastExchangeTime,omitempty"`

	// TokenExpiresAt is the expiry time of the token currently stored in the
	// target Secret.
	// +optional
	TokenExpiresAt *metav1.Time `json:"tokenExpiresAt,omitempty"`

	// IssuedTokenType is the token type returned by authentik.
	// +optional
	IssuedTokenType string `json:"issuedTokenType,omitempty"`

	// Scope lists the scopes granted on the issued token.
	// +optional
	Scope string `json:"scope,omitempty"`
}

// TokenExchangeRequest is the Schema for the tokenexchangerequests API.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ServiceAccount",type=string,JSONPath=`.spec.serviceAccount.name`
// +kubebuilder:printcolumn:name="Audience",type=string,JSONPath=`.spec.audience`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.tokenExpiresAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type TokenExchangeRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TokenExchangeRequestSpec   `json:"spec,omitempty"`
	Status TokenExchangeRequestStatus `json:"status,omitempty"`
}

// TokenExchangeRequestList contains a list of TokenExchangeRequest.
// +kubebuilder:object:root=true
type TokenExchangeRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TokenExchangeRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TokenExchangeRequest{}, &TokenExchangeRequestList{})
}
