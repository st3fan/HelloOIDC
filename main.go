package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

//go:generate npm ci --silent
//go:generate npx tailwindcss -i styles.css -o app.css --minify

//go:embed page.html
var pageHTML string

//go:embed app.css
var appCSS []byte

var page = template.Must(template.New("page").Parse(pageHTML))

type session struct{ email, idToken string }

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if fallback == "" {
		log.Fatalf("%s is required", key)
	}
	return fallback
}

func randomString() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	issuer := env("OIDC_ISSUER", "")
	baseURL := env("BASE_URL", "http://localhost:8080")
	listen := env("LISTEN_ADDR", ":8080")
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: 10 * time.Second})
	handler, err := newHandler(ctx, issuer, baseURL, env("OIDC_CLIENT_ID", ""), os.Getenv("OIDC_CLIENT_SECRET"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Hello OIDC listening on %s (%s)", listen, baseURL)
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func newHandler(ctx context.Context, issuer, baseURL, clientID, clientSecret string) (http.Handler, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	base, err := url.Parse(baseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("BASE_URL must be an HTTP(S) origin, such as http://localhost:8080")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  baseURL + "/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}
	if clientSecret == "" {
		// Public clients identify themselves in the form, without HTTP Basic auth.
		config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	var discovery struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, fmt.Errorf("invalid OIDC discovery: %w", err)
	}
	endSession, err := url.Parse(discovery.EndSessionEndpoint)
	if err != nil || (discovery.EndSessionEndpoint != "" && (endSession.Host == "" || (endSession.Scheme != "http" && endSession.Scheme != "https"))) {
		return nil, fmt.Errorf("invalid end_session_endpoint")
	}
	var mu sync.Mutex
	sessions := map[string]session{}
	setCookie := func(w http.ResponseWriter, name, value string, maxAge int) {
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: base.Scheme == "https", SameSite: http.SameSiteLaxMode})
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		email := ""
		if c, err := r.Cookie("session"); err == nil {
			mu.Lock()
			email = sessions[c.Value].email
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, email); err != nil {
			log.Printf("render page: %v", err)
		}
	})

	mux.HandleFunc("GET /app.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(appCSS)
	})

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		state, nonce, pkce := randomString(), randomString(), oauth2.GenerateVerifier()
		setCookie(w, "state", state, 300)
		setCookie(w, "nonce", nonce, 300)
		setCookie(w, "pkce", pkce, 300)
		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)), http.StatusFound)
	})

	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		state, err1 := r.Cookie("state")
		nonce, err2 := r.Cookie("nonce")
		pkce, err3 := r.Cookie("pkce")
		if err1 != nil || err2 != nil || err3 != nil || state.Value == "" || nonce.Value == "" || pkce.Value == "" || r.URL.Query().Get("state") != state.Value {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		for _, name := range []string{"state", "nonce", "pkce"} {
			setCookie(w, name, "", -1)
		}
		if e := r.URL.Query().Get("error"); e != "" {
			http.Error(w, "sign in failed: "+e+" "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
			return
		}
		exchangeCtx := context.WithValue(r.Context(), oauth2.HTTPClient, oauth2.NewClient(ctx, nil))
		token, err := config.Exchange(exchangeCtx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkce.Value))
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}
		rawIDToken, _ := token.Extra("id_token").(string)
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil || idToken.Nonce != nonce.Value {
			http.Error(w, "invalid ID token", http.StatusBadRequest)
			return
		}
		var claims struct {
			Email string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil || claims.Email == "" {
			http.Error(w, "ID token has no email claim", http.StatusBadRequest)
			return
		}
		id := randomString()
		mu.Lock()
		if c, err := r.Cookie("session"); err == nil {
			delete(sessions, c.Value)
		}
		sessions[id] = session{claims.Email, rawIDToken}
		mu.Unlock()
		setCookie(w, "session", id, 0)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		var s session
		if c, err := r.Cookie("session"); err == nil {
			mu.Lock()
			s = sessions[c.Value]
			delete(sessions, c.Value)
			mu.Unlock()
		}
		setCookie(w, "session", "", -1)
		if discovery.EndSessionEndpoint == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		// Also end the session at SoloID, which then sends the browser back here.
		target := *endSession
		q := target.Query()
		q.Set("client_id", config.ClientID)
		q.Set("post_logout_redirect_uri", baseURL+"/")
		if s.idToken != "" {
			q.Set("id_token_hint", s.idToken)
		}
		target.RawQuery = q.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})

	protected := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "same-origin")
		protected.ServeHTTP(w, r)
	}), nil
}
