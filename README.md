# HelloOIDC

A minimal Go app that signs you in with [SoloID](https://github.com/st3fan/SoloID) over OpenID Connect.

## Setup

Requires Go 1.27.4+ and a running SoloID.

1. Add this entry to SoloID's `clients` array and reload its config:

```json
{
  "client_id": "hellooidc",
  "public": true,
  "redirect_uris": ["http://localhost:8080/callback"],
  "post_logout_redirect_uris": ["http://localhost:8080/"]
}
```

2. Run:

```sh
export OIDC_ISSUER=https://soloid.example.com
export OIDC_CLIENT_ID=hellooidc
go run .
```

3. Open http://localhost:8080.

**Log out** clears this app's session, then asks SoloID to sign you out and return
here. Sessions live in memory; restarting this app clears them.

## Environment variables

| Variable | Default | |
|---|---|---|
| `OIDC_ISSUER` | required | SoloID issuer URL |
| `OIDC_CLIENT_ID` | required | |
| `OIDC_CLIENT_SECRET` | empty | Only for confidential clients |
| `BASE_URL` | `http://localhost:8080` | Public origin, without a path. Use HTTPS outside localhost. |
| `LISTEN_ADDR` | `:8080` | |

If you change `BASE_URL`, register `$BASE_URL/callback` for sign-in and
`$BASE_URL/` for sign-out in SoloID (the trailing slash matters).

## Development

`go build .` builds a standalone binary. `go test -race ./...` runs the tests.

HTML and compiled Tailwind CSS are embedded; running needs no Node or CDN.
After editing `page.html` or `styles.css`, run `go generate` (needs Node 22+) and
commit the regenerated `app.css`. See [PLAN.md](PLAN.md) for scope.
