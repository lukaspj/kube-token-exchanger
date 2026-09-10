// Package authentik implements a client for authentik's RFC 8693 OAuth2
// token exchange endpoint.
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
	// GrantTypeTokenExchange is the RFC 8693 token exchange grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// TokenTypeJWT is the OAuth2 token type identifier for JWTs. Kubernetes
	// ServiceAccount tokens are JWTs.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// DefaultTokenPath is the authentik token endpoint path.
	DefaultTokenPath = "/application/o/token/"
)

// Config holds the connection settings for the authentik token endpoint.
type Config struct {
	URL          string
	TokenPath    string
	// Scopes are the default OAuth2 scopes requested on exchanged tokens.
	Scopes       []string
	// ClientID identifies the OAuth2 client performing the exchange. When
	// set with ClientSecret, credentials are sent as HTTP Basic auth;
	// without a secret the client is treated as public and only client_id
	// is sent in the form body.
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
	InsecureTLS  bool
	CACert       []byte
	HTTPClient   *http.Client
}

// ExchangeRequest is a token exchange request.
type ExchangeRequest struct {
	// SubjectToken is the token presented for exchange (a Kubernetes
	// ServiceAccount JWT).
	SubjectToken string
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

// Client performs token exchanges against an authentik instance.
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

// Exchange performs an RFC 8693 token exchange, presenting the Kubernetes
// ServiceAccount JWT as subject token and receiving an authentik identity
// token in return.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResponse, error) {
	if req.SubjectToken == "" {
		return nil, errors.New("authentik: subject token is required")
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = c.cfg.Scopes
	}

	form := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {req.SubjectToken},
		"subject_token_type": {TokenTypeJWT},
		"scope":              {strings.Join(scopes, " ")},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authentik: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	if c.cfg.ClientID != "" {
		if c.cfg.ClientSecret != "" {
			httpReq.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
		} else {
			form.Set("client_id", c.cfg.ClientID)
			httpReq.Body = io.NopCloser(strings.NewReader(form.Encode()))
			httpReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(form.Encode())), nil
			}
		}
	}

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
			return nil, fmt.Errorf("authentik: token exchange rejected: %s", oaErr.message())
		}
		return nil, fmt.Errorf("authentik: token exchange failed with status %d: %s", resp.StatusCode, truncate(string(body), 200))
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
