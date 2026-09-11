// Package authentik implements a client for authentik's OAuth2 token
// endpoint. It authenticates using the client_credentials grant with a JWT
// client assertion (RFC 7523), so no client secret is required.
package authentik

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// GrantTypeClientCredentials is the OAuth2 client credentials grant type.
	GrantTypeClientCredentials = "client_credentials"

	// ClientAssertionTypeJWTBearer is the RFC 7523 JWT bearer client
	// assertion type. Kubernetes ServiceAccount tokens are JWTs.
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// DefaultTokenPath is the authentik token endpoint path.
	DefaultTokenPath = "/application/o/token/"
)

// Config holds the connection settings for the authentik token endpoint.
type Config struct {
	URL          string
	TokenPath    string
	// Scopes are the default OAuth2 scopes requested on issued tokens.
	Scopes []string
	// ClientID identifies the OAuth2 client performing the request. It is
	// sent in the form body; authentication happens via the JWT client
	// assertion, no client secret is used.
	ClientID     string
	Timeout      time.Duration
	InsecureTLS  bool
	CACert       []byte
	HTTPClient   *http.Client
}

// ExchangeRequest is a client credentials token request authenticated with a
// JWT client assertion.
type ExchangeRequest struct {
	// ClientAssertion is the JWT presented as client assertion (a Kubernetes
	// ServiceAccount JWT).
	ClientAssertion string
	// Scopes are the requested OAuth2 scopes.
	Scopes []string
}

// ExchangeResponse is the token endpoint response for a successful exchange.
type ExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type"`
}

// Expiry returns the expiry time derived from the response.
func (r *ExchangeResponse) Expiry(now time.Time) time.Time {
	return now.Add(time.Duration(r.ExpiresIn) * time.Second)
}

// Client performs token requests against an authentik instance.
type Client struct {
	cfg   Config
	http  *http.Client
	token string // fully resolved token endpoint URL
}

// New builds a Client from the given configuration.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("authentik: URL is required")
	}

	tokenPath := cfg.TokenPath
	if tokenPath == "" {
		tokenPath = DefaultTokenPath
	}
	tokenURL, err := url.JoinPath(cfg.URL, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("authentik: resolving token endpoint: %w", err)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 15 * time.Second
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS} //nolint:gosec // opt-in per spec
		if len(cfg.CACert) > 0 {
			pool, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("authentik: loading system cert pool: %w", err)
			}
			if !pool.AppendCertsFromPEM(cfg.CACert) {
				return nil, errors.New("authentik: no valid certificates in caCert")
			}
			tlsConfig.RootCAs = pool
		}
		httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: tlsConfig,
			},
		}
	}

	return &Client{cfg: cfg, http: httpClient, token: tokenURL}, nil
}

// oauthError is the error body returned by the token endpoint on failure.
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e oauthError) message() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.Error, e.ErrorDescription)
	}
	return e.Error
}

// Exchange authenticates against authentik's token endpoint using the
// client_credentials grant with the Kubernetes ServiceAccount JWT as client
// assertion, and returns the issued authentik identity token.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResponse, error) {
	if req.ClientAssertion == "" {
		return nil, errors.New("authentik: client assertion is required")
	}
	if c.cfg.ClientID == "" {
		return nil, errors.New("authentik: client ID is required")
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = c.cfg.Scopes
	}

	form := url.Values{
		"grant_type":            {GrantTypeClientCredentials},
		"client_id":             {c.cfg.ClientID},
		"client_assertion_type": {ClientAssertionTypeJWTBearer},
		"client_assertion":      {req.ClientAssertion},
		"scope":                 {strings.Join(scopes, " ")},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authentik: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("authentik: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("authentik: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oaErr oauthError
		if jsonErr := json.Unmarshal(body, &oaErr); jsonErr == nil && oaErr.Error != "" {
			return nil, fmt.Errorf("authentik: token request rejected: %s", oaErr.message())
		}
		return nil, fmt.Errorf("authentik: token request failed with status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var out ExchangeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("authentik: decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("authentik: token response missing access_token")
	}
	return &out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
