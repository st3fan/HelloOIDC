package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Exercise the app's HTTP interface against discovery, JWKS and token endpoints
// that issue real signed tokens. No verifier or session-store mocks.
func testApp(t *testing.T, baseURL, secret, logoutPath, fault string) http.Handler {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			doc := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"}}
			if logoutPath != "" {
				doc["end_session_endpoint"] = issuer + logoutPath
			}
			json.NewEncoder(w).Encode(doc)
		case "/jwks":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			r.ParseForm()
			id, password, basic := r.BasicAuth()
			if secret == "" {
				if basic || r.Form.Get("client_id") != "hello" || r.Form.Has("client_secret") {
					http.Error(w, `{"error":"invalid_client"}`, 401)
					return
				}
			} else if !basic || id != "hello" || password != secret {
				http.Error(w, `{"error":"invalid_client"}`, 401)
				return
			}
			// The test hands the original authorization request back as its code.
			auth, _ := url.ParseQuery(r.Form.Get("code"))
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != strings.TrimRight(baseURL, "/")+"/callback" || auth.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(hash[:]) {
				http.Error(w, `{"error":"invalid_grant"}`, 400)
				return
			}
			claims := map[string]any{"iss": issuer, "sub": "user-123", "aud": "hello",
				"exp": time.Now().Add(time.Minute).Unix(), "nonce": auth.Get("nonce"), "email": "jane@example.com"}
			switch fault {
			case "nonce":
				claims["nonce"] = "wrong-nonce"
			case "audience":
				claims["aud"] = "another-client"
			case "issuer":
				claims["iss"] = "https://wrong.example"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "email":
				delete(claims, "email")
			}
			payload, _ := json.Marshal(claims)
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			raw, _ := signed.CompactSerialize()
			if fault == "signature" {
				parts := strings.Split(raw, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 256))
				raw = strings.Join(parts, ".")
			}
			if fault == "missing token" {
				raw = ""
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "test-access-token", "token_type": "Bearer", "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	issuer = provider.URL
	h, err := newHandler(context.Background(), issuer, baseURL, "hello", secret)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(h http.Handler, method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func startLogin(t *testing.T, h http.Handler) (url.Values, []*http.Cookie) {
	t.Helper()
	w := request(h, "GET", "/login")
	if w.Code != http.StatusFound {
		t.Fatalf("login status: %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("scope") != "openid email" || q.Get("response_type") != "code" || q.Get("client_id") != "hello" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("invalid authorization request: %v", q)
	}
	return q, w.Result().Cookies()
}

func callbackPath(auth url.Values) string {
	return "/callback?" + url.Values{"state": {auth.Get("state")}, "code": {auth.Encode()}}.Encode()
}

func TestLoginAndLogout(t *testing.T) {
	for _, tc := range []struct{ name, base, secret, logout string }{
		{"public", "http://localhost:8080", "", "/logout?tenant=solo"},
		{"confidential HTTPS", "https://app.example/", "test-secret", "/logout?tenant=solo"},
		{"local fallback", "http://localhost:8080", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testApp(t, tc.base, tc.secret, tc.logout, "")
			if w := request(h, "GET", "/"); !strings.Contains(w.Body.String(), "Sign in with SoloID") {
				t.Fatal("missing sign-in button")
			}
			auth, cookies := startLogin(t, h)
			for _, c := range cookies {
				if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != strings.HasPrefix(tc.base, "https:") || c.MaxAge != 300 {
					t.Errorf("unsafe transaction cookie: %s", c.Name)
				}
			}
			w := request(h, "GET", callbackPath(auth), cookies...)
			if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
				t.Fatalf("callback: %d %s", w.Code, w.Body.String())
			}
			var sessionCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "session" {
					sessionCookie = c
				} else if c.MaxAge != -1 {
					t.Errorf("transaction cookie not cleared: %s", c.Name)
				}
			}
			if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.Secure != strings.HasPrefix(tc.base, "https:") {
				t.Fatal("missing or unsafe session cookie")
			}
			w = request(h, "GET", "/", sessionCookie)
			if !strings.Contains(w.Body.String(), "jane@example.com") || !strings.Contains(w.Body.String(), "Hello, world!") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing dashboard or cache protection")
			}
			w = request(h, "POST", "/logout", sessionCookie)
			if w.Code != http.StatusFound || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
				t.Fatal("logout did not redirect and clear cookie")
			}
			if tc.logout == "" {
				if w.Header().Get("Location") != "/" {
					t.Fatal("missing local fallback")
				}
			} else {
				u, _ := url.Parse(w.Header().Get("Location"))
				q := u.Query()
				if u.Path != "/logout" || q.Get("tenant") != "solo" || q.Get("client_id") != "hello" || q.Get("post_logout_redirect_uri") != strings.TrimRight(tc.base, "/")+"/" || len(strings.Split(q.Get("id_token_hint"), ".")) != 3 {
					t.Fatal("incorrect end-session redirect")
				}
				payload, err := base64.RawURLEncoding.DecodeString(strings.Split(q.Get("id_token_hint"), ".")[1])
				var claims map[string]any
				if err != nil || json.Unmarshal(payload, &claims) != nil || claims["nonce"] != auth.Get("nonce") || claims["email"] != "jane@example.com" {
					t.Fatal("logout hint is not this session's ID token")
				}
			}
			// Reusing the old cookie must fail even before SoloID confirms logout.
			if w = request(h, "GET", "/", sessionCookie); strings.Contains(w.Body.String(), "jane@example.com") || !strings.Contains(w.Body.String(), "Sign in with SoloID") {
				t.Fatal("server-side session survived logout")
			}
			w = request(h, "POST", "/logout", sessionCookie)
			u, _ := url.Parse(w.Header().Get("Location"))
			if u.Query().Has("id_token_hint") {
				t.Fatal("logout reused an invalidated session's token")
			}
		})
	}
}

func TestRejectInvalidLogin(t *testing.T) {
	for _, fault := range []string{"state", "empty state", "missing cookies", "nonce", "audience", "issuer", "expired", "email", "signature", "missing token"} {
		t.Run(fault, func(t *testing.T) {
			h := testApp(t, "http://localhost:8080", "", "/logout", fault)
			auth, cookies := startLogin(t, h)
			switch fault {
			case "state":
				auth.Set("state", "wrong-state")
			case "empty state":
				auth.Set("state", "")
				for _, c := range cookies {
					if c.Name == "state" {
						c.Value = ""
					}
				}
			case "missing cookies":
				cookies = nil
			}
			w := request(h, "GET", callbackPath(auth), cookies...)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid login accepted: %d %s", w.Code, w.Body.String())
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == "session" && c.Value != "" {
					t.Fatal("session created for invalid login")
				}
			}
		})
	}
}

func TestRejectCrossOriginLogout(t *testing.T) {
	h := testApp(t, "http://localhost:8080", "", "/logout", "")
	r := httptest.NewRequest("POST", "http://localhost:8080/logout", nil)
	r.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Fatal("cross-origin logout was not blocked")
	}
}
