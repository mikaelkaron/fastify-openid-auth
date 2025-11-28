

# fastify-openid-auth

`fastify-openid-auth` is a Fastify plugin for OpenID Connect authentication using [openid-client](https://github.com/panva/node-openid-client). It supports both bearer token and cookie-based authentication, with flexible token management and full TypeScript support.

## Features

- OpenID Connect authentication for Fastify
- Bearer token and cookie-based authentication flows
- Customizable token reading/writing (headers, cookies, session)
- Decorates Fastify instance with authentication handlers: `login`, `verify`, `refresh`, `logout`
- TypeScript types for handlers and tokens

## Installation

```bash
npm install fastify-openid-auth
```


## `openIDHandlersFactory`

The core of this library is the `openIDHandlersFactory`, which creates handlers for OpenID Connect authentication. You can use it directly for custom integration, testing, or advanced scenarios:

```ts
import { openIDHandlersFactory } from 'fastify-openid-auth'

const config = { /* openid-client config */ }
const { login, verify, refresh, logout } = openIDHandlersFactory(config, {
	login: { /* login handler options */ },
	verify: { /* verify handler options */ },
	refresh: { /* refresh handler options */ },
	logout: { /* logout handler options */ }
})

// Use login, verify, refresh, logout as Fastify route handlers
```

## `openIDAuthPlugin`

For most users, it's easiest to use the Fastify plugin wrapper, which registers and decorates your Fastify instance with the authentication handlers:

```ts
import Fastify from 'fastify'
import openIDAuthPlugin from 'fastify-openid-auth'

const fastify = Fastify()
const AUTH_HANDLERS = Symbol.for('auth-handlers')

fastify.register(openIDAuthPlugin, {
	decorator: AUTH_HANDLERS,
	config: { /* openid-client config */ },
	login: { /* login handler options */ },
	verify: { /* verify handler options */ },
	refresh: { /* refresh handler options */ },
	logout: { /* logout handler options */ }
})

const { login, verify, refresh, logout } = fastify[AUTH_HANDLERS]

// Use login, verify, refresh, logout as Fastify route handlers
```

### Configuration Options

- `decorator`: string or symbol to decorate Fastify instance
- `config`: openid-client configuration object
- `login`, `verify`, `refresh`, `logout`: handler options

### Token Management

You provide functions to read and write tokens, e.g.:

- **Bearer tokens**: Read from `Authorization` header
- **Cookie tokens**: Read/write from cookies or session

See the example projects for real implementations.

## Examples

- [`examples/basic`](examples/basic) — Bearer token authentication
- [`examples/cookies`](examples/cookies) — Cookie token authentication

## License

MIT
