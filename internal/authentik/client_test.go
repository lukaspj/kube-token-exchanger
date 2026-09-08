package authentik

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeTransport captures the request and returns a canned response without
// touching the network.
type fakeTransport struct {
	t        *testing.T
	handler  func(req *http.Request) *http.Response
	lastReq  *http.Request
	lastForm url.Values
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.lastReq = req
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			f.t.Fatalf("reading request body: %v", err)
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		form, err := url.ParseQuery(string(body))
		if err != nil {
			f.t.Fatalf("parsing form body: %v", err)
		}
		f.lastForm = form
	}
	return f.handler(req), nil
}

func jsonResponse(status int, body string) func(*http.Request) *http.Response {
	return func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}
	}
}

func newTestClient(t *testing.T, handler func(req *http.Request) *http.Response) (*Client, *fakeTransport) {
	t.Helper()
	ft := &fakeTransport{t: t, handler: handler}
	client, err := New(Config{
		URL:          "https://authentik.example.com",
		ClientID:     "cid",
		ClientSecret: "csec",
		HTTPClient:   &http.Client{Transport: ft},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, ft
}

func TestExchangeSuccess(t *testing.T) {
	client, ft := newTestClient(t, jsonResponse(http.StatusOK, `{
		"access_token": "authentik.jwt.token",
		"token_type": "Bearer",
		"expires_in": 3600,
		"scope": "openid email",
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
	}`))

	now := time.Now()
	resp, err := client.Exchange(context.Background(), ExchangeRequest{
		SubjectToken: "k8s-sa-jwt",
		Scopes:       []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if ft.lastReq.URL.Path != "/application/o/token/" {
		t.Errorf("path = %q, want /application/o/token/", ft.lastReq.URL.Path)
	}
	if ct := ft.lastReq.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("content type = %q", ct)
	}

	want := map[string]string{
		"grant_type":         GrantTypeTokenExchange,
		"client_id":          "cid",
		"client_secret":      "csec",
		"subject_token":      "k8s-sa-jwt",
		"subject_token_type": TokenTypeJWT,
		"scope":              "openid email",
	}
	for k, v := range want {
		if got := ft.lastForm.Get(k); got != v {
			t.Errorf("form field %s = %q, want %q", k, got, v)
		}
	}

	if resp.AccessToken != "authentik.jwt.token" {
		t.Errorf("access token = %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token type = %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d", resp.ExpiresIn)
	}
	if !resp.Expiry(now).Equal(now.Add(3600 * time.Second)) {
		t.Errorf("expiry = %v, want %v", resp.Expiry(now), now.Add(3600*time.Second))
	}
	if resp.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued token type = %q", resp.IssuedTokenType)
	}
}

func TestExchangeOAuthError(t *testing.T) {
	client, _ := newTestClient(t, jsonResponse(http.StatusBadRequest,
		`{"error": "invalid_grant", "error_description": "token not trusted"}`))

	_, err := client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "jwt"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid_grant") || !strings.Contains(err.Error(), "token not trusted") {
		t.Errorf("error = %v", err)
	}
}

func TestExchangeHTTPError(t *testing.T) {
	client, _ := newTestClient(t, func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("boom")),
			Request:    req,
		}
	})

	_, err := client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "jwt"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []Config{
		{URL: "", ClientID: "cid", ClientSecret: "sec"},
		{URL: "http://x", ClientID: "", ClientSecret: "sec"},
		{URL: "http://x", ClientID: "cid", ClientSecret: ""},
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) expected error", cfg)
		}
	}
}

func TestCustomTokenPath(t *testing.T) {
	client, ft := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at", "expires_in": 60}`))
	client.cfg.TokenPath = "/custom/token"
	client.token = "https://authentik.example.com/custom/token"

	if _, err := client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "jwt"}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ft.lastReq.URL.Path != "/custom/token" {
		t.Errorf("path = %q, want /custom/token", ft.lastReq.URL.Path)
	}
}

func TestScopeEncoding(t *testing.T) {
	client, ft := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at", "expires_in": 60}`))

	if _, err := client.Exchange(context.Background(), ExchangeRequest{
		SubjectToken: "jwt",
		Scopes:       []string{"openid", "profile"},
	}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ft.lastForm.Get("scope") != "openid profile" {
		t.Errorf("scope = %q", ft.lastForm.Get("scope"))
	}
}

func TestExchangeEmptySubject(t *testing.T) {
	client, _ := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at"}`))
	if _, err := client.Exchange(context.Background(), ExchangeRequest{}); err == nil {
		t.Fatal("expected error for empty subject token")
	}
}

func newPrivateKeyJWTClient(t *testing.T, handler func(req *http.Request) *http.Response) (*Client, *fakeTransport) {
	t.Helper()
	ft := &fakeTransport{t: t, handler: handler}
	client, err := New(Config{
		URL:              "https://authentik.example.com",
		ClientID:         "cid",
		ClientAuthMethod: ClientAuthPrivateKeyJWT,
		HTTPClient:       &http.Client{Transport: ft},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, ft
}

func TestExchangePrivateKeyJWT(t *testing.T) {
	client, ft := newPrivateKeyJWTClient(t, jsonResponse(http.StatusOK, `{"access_token": "at", "expires_in": 60}`))

	resp, err := client.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:    "k8s-sa-jwt",
		ClientAssertion: "assertion-jwt",
		Scopes:          []string{"openid"},
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken != "at" {
		t.Errorf("access token = %q", resp.AccessToken)
	}

	want := map[string]string{
		"grant_type":            GrantTypeTokenExchange,
		"client_id":             "cid",
		"client_assertion_type": ClientAssertionTypeJWTBearer,
		"client_assertion":      "assertion-jwt",
		"subject_token":         "k8s-sa-jwt",
		"subject_token_type":    TokenTypeJWT,
		"scope":                 "openid",
	}
	for k, v := range want {
		if got := ft.lastForm.Get(k); got != v {
			t.Errorf("form field %s = %q, want %q", k, got, v)
		}
	}
	if _, ok := ft.lastForm["client_secret"]; ok {
		t.Error("client_secret must not be sent with privateKeyJwt")
	}
}

func TestExchangePrivateKeyJWTMissingAssertion(t *testing.T) {
	client, _ := newPrivateKeyJWTClient(t, jsonResponse(http.StatusOK, `{"access_token": "at"}`))
	if _, err := client.Exchange(context.Background(), ExchangeRequest{SubjectToken: "jwt"}); err == nil {
		t.Fatal("expected error for missing client assertion")
	}
}

func TestNewPrivateKeyJWTValidation(t *testing.T) {
	cfg := Config{URL: "http://x", ClientID: "cid", ClientAuthMethod: ClientAuthPrivateKeyJWT}
	if _, err := New(cfg); err != nil {
		t.Errorf("New(%+v): %v, want no error without client secret", cfg, err)
	}

	cases := []Config{
		{URL: "http://x", ClientID: "", ClientAuthMethod: ClientAuthPrivateKeyJWT},
		{URL: "http://x", ClientID: "cid", ClientAuthMethod: "unsupported"},
	}
	for _, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("New(%+v) expected error", c)
		}
	}
}
