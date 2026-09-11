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
		URL:        "https://authentik.example.com",
		ClientID:   "my-app",
		HTTPClient: &http.Client{Transport: ft},
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
		"scope": "openid email"
	}`))

	now := time.Now()
	resp, err := client.Exchange(context.Background(), ExchangeRequest{
		ClientAssertion: "k8s-sa-jwt",
		Scopes:          []string{"openid", "email"},
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
		"grant_type":            GrantTypeClientCredentials,
		"client_id":             "my-app",
		"client_assertion_type": ClientAssertionTypeJWTBearer,
		"client_assertion":      "k8s-sa-jwt",
		"scope":                 "openid email",
	}
	for k, v := range want {
		if got := ft.lastForm.Get(k); got != v {
			t.Errorf("form field %s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"client_secret", "subject_token", "subject_token_type"} {
		if _, ok := ft.lastForm[k]; ok {
			t.Errorf("form field %s must not be sent", k)
		}
	}
	if _, _, ok := ft.lastReq.BasicAuth(); ok {
		t.Error("basic auth must not be sent")
	}

	if resp.AccessToken != "authentik.jwt.token" {
		t.Errorf("access token = %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token type = %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expires in = %d", resp.ExpiresIn)
	}
	if resp.Scope != "openid email" {
		t.Errorf("scope = %q", resp.Scope)
	}
	expiry := resp.Expiry(now)
	if expiry.Sub(now) != 3600*time.Second {
		t.Errorf("expiry delta = %v, want 3600s", expiry.Sub(now))
	}
}

func TestExchangeClientIDFromConfig(t *testing.T) {
	client, ft := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at", "expires_in": 60}`))

	if _, err := client.Exchange(context.Background(), ExchangeRequest{ClientAssertion: "jwt"}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if got := ft.lastForm.Get("client_id"); got != "my-app" {
		t.Errorf("form client_id = %q, want my-app", got)
	}
	if _, _, ok := ft.lastReq.BasicAuth(); ok {
		t.Error("basic auth must not be sent")
	}
	if _, ok := ft.lastForm["client_secret"]; ok {
		t.Error("client_secret must not be sent")
	}
}

func TestExchangeMissingClientID(t *testing.T) {
	client, _ := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at"}`))
	client.cfg.ClientID = ""

	if _, err := client.Exchange(context.Background(), ExchangeRequest{ClientAssertion: "jwt"}); err == nil {
		t.Fatal("expected error for missing client ID")
	}
}

func TestExchangeMissingAssertion(t *testing.T) {
	client, _ := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at"}`))

	if _, err := client.Exchange(context.Background(), ExchangeRequest{}); err == nil {
		t.Fatal("expected error for missing client assertion")
	}
}

func TestExchangeOAuthError(t *testing.T) {
	client, _ := newTestClient(t, jsonResponse(http.StatusBadRequest,
		`{"error": "invalid_client", "error_description": "JWT not trusted"}`))

	_, err := client.Exchange(context.Background(), ExchangeRequest{ClientAssertion: "jwt"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid_client") || !strings.Contains(err.Error(), "JWT not trusted") {
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

	_, err := client.Exchange(context.Background(), ExchangeRequest{ClientAssertion: "jwt"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{URL: ""}); err == nil {
		t.Error("New without URL expected error")
	}
}

func TestCustomTokenPath(t *testing.T) {
	client, ft := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at", "expires_in": 60}`))
	client.cfg.TokenPath = "/custom/token"
	client.token = "https://authentik.example.com/custom/token"

	if _, err := client.Exchange(context.Background(), ExchangeRequest{ClientAssertion: "jwt"}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ft.lastReq.URL.Path != "/custom/token" {
		t.Errorf("path = %q, want /custom/token", ft.lastReq.URL.Path)
	}
}

func TestScopeEncoding(t *testing.T) {
	client, ft := newTestClient(t, jsonResponse(http.StatusOK, `{"access_token": "at", "expires_in": 60}`))

	if _, err := client.Exchange(context.Background(), ExchangeRequest{
		ClientAssertion: "jwt",
		Scopes:          []string{"openid", "profile"},
	}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ft.lastForm.Get("scope") != "openid profile" {
		t.Errorf("scope = %q", ft.lastForm.Get("scope"))
	}
}
