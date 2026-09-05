// Package kubernetes provides helpers for minting and inspecting Kubernetes
// ServiceAccount identity tokens.
package kubernetes

import (
	"context"
	"fmt"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Minter mints bound ServiceAccount tokens via the TokenRequest API.
type Minter struct {
	client kubernetes.Interface
}

// NewMinter builds a Minter backed by the given Kubernetes client.
func NewMinter(client kubernetes.Interface) *Minter {
	return &Minter{client: client}
}

// Mint requests a bound ServiceAccount token for the given account and
// audiences with the requested lifetime. It returns the raw JWT.
func (m *Minter) Mint(ctx context.Context, namespace, name string, audiences []string, lifetime time.Duration) (string, error) {
	ttl := int64(lifetime.Round(time.Second).Seconds())
	req, err := m.client.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: &ttl,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("minting ServiceAccount token for %s/%s: %w", namespace, name, err)
	}
	if req.Status.Token == "" {
		return "", fmt.Errorf("minting ServiceAccount token for %s/%s: empty token returned", namespace, name)
	}
	return req.Status.Token, nil
}
