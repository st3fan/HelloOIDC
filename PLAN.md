# Hello OIDC

## Goal

A tiny Go app that proves sign-in and sign-out work with SoloID. No database,
frontend runtime, or real dashboard features.

## Experience

- Always show **Hello OIDC** at the top left.
- Signed out: a welcome card with **Sign in with SoloID**.
- Signed in: **Hello, world!**, with the user's email and **Log out** in the header.
- Match SoloID's Tailwind v4 stone palette and shadcn-style cards and buttons,
  using server-rendered HTML rather than React components. Support narrow screens.

## Authentication

- Discover SoloID's endpoints from `OIDC_ISSUER`.
- Use authorization code flow, S256 PKCE, random state and nonce, and the
  `openid email` scopes. Validate the ID token with `go-oidc` before creating a session.
- Keep the email and ID token server-side in memory; send only an opaque session
  cookie to the browser. Use HttpOnly, SameSite=Lax, and Secure when served over HTTPS.
- Log out locally first, then redirect to the discovered `end_session_endpoint`
  (SoloID's `/logout`) with the ID token hint, client ID, and registered return URL.
  SoloID handles its confirmation page and returns to the signed-out app.
- Fall back to local logout if the provider does not advertise end-session support.
- Restarting the app clears its sessions. No refresh tokens, user management,
  persistent sessions, or coordinated/back-channel logout.

## Configuration and delivery

- Environment only: required `OIDC_ISSUER` and `OIDC_CLIENT_ID`; optional
  `OIDC_CLIENT_SECRET`, `BASE_URL` (default `http://localhost:8080`), and
  `LISTEN_ADDR` (default `:8080`).
- Register `$BASE_URL/callback` and `$BASE_URL/` in SoloID for login and logout.
- Embed HTML and compiled CSS in the Go binary. Check in the CSS so normal builds
  need only Go; Node is needed only for `go generate` after styling changes.
- Keep the README short: client registration, environment, run/build, CSS rebuild.

## Verification

- Run Go formatting, vet, build, and race-enabled HTTP-flow tests.
- Test successful login/logout and rejection of invalid state and ID tokens.
- Check logout parameters, query preservation, local-session invalidation, and
  the fallback for providers without an end-session endpoint.
- Rebuild CSS from the lockfile and check the output is reproducible.
- Exercise login, dashboard, SoloID logout confirmation, return, and a fresh
  sign-in using a disposable local SoloID instance. Inspect desktop and narrow
  layouts and capture the logout interaction.
- Deliver the plan and working app in a PR; do not merge or deploy it.
