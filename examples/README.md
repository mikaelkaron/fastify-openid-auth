# Examples

This directory contains runnable examples demonstrating how to use `fastify-openid-auth` with different token storage strategies.

## Prerequisites

1. **Docker** - for running Keycloak
2. **Node.js 22+** - for `--env-file` support

## Setup

### Start Keycloak

```bash
cd examples
docker compose up -d
```

This starts Keycloak at http://localhost:8080 with a pre-configured realm:
- **Realm:** `example`
- **Client:** `example-app` (secret: `example-secret`)
- **Test user:** `test` / `test`

## Running Examples

### Basic (Bearer Token)

Reads access token from `Authorization: Bearer` header. Returns tokens as JSON after login.

```bash
node --env-file=examples/basic/.env.local --import tsx examples/basic/server.ts
```

**Endpoints:**
- `GET /` - API info
- `GET /login` - Redirects to Keycloak, returns tokens as JSON
- `GET /protected` - Requires `Authorization: Bearer <access_token>`
- `POST /refresh` - Refresh tokens
- `GET /logout` - End session

### Cookies

Stores tokens in separate HTTP-only cookies (`access_token`, `refresh_token`, `id_token`).

```bash
node --env-file=examples/cookies/.env.local --import tsx examples/cookies/server.ts
```

**Endpoints:**
- `GET /` - Shows login status
- `GET /login` - Redirects to Keycloak
- `GET /callback` - OAuth callback
- `GET /protected` - Requires valid token cookie
- `GET /refresh` - Refresh tokens
- `GET /logout` - Clear cookies and end session

### Session (Encrypted Cookie)

Stores all tokens in a single encrypted session cookie using `@fastify/secure-session`.

```bash
node --env-file=examples/session/.env.local --import tsx examples/session/server.ts
```

**Endpoints:**
- `GET /` - Shows login status and token info
- `GET /login` - Redirects to Keycloak
- `GET /callback` - OAuth callback
- `GET /protected` - Requires valid session
- `GET /refresh` - Refresh tokens
- `GET /logout` - Clear session and end session

## Testing

1. Open http://localhost:3000
2. Click login or navigate to `/login`
3. Login with `test` / `test`
4. You'll be redirected back with tokens

## Cleanup

```bash
cd examples
docker compose down
```
