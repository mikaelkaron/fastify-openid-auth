import cookie, { type CookieSerializeOptions } from '@fastify/cookie'
import createError from '@fastify/error'
import secureSession from '@fastify/secure-session'
import Fastify from 'fastify'
import { createRemoteJWKSet } from 'jose'
import { allowInsecureRequests } from 'openid-client'
import openIDAuthPlugin, {
  discovery,
  type OpenIDAuthHandlers,
  type OpenIDReadTokens,
  type OpenIDSession,
  type OpenIDWriteTokens,
  type TokenEndpointResponse
} from '../../src/index.ts'

const AUTH_HANDLERS = Symbol.for('auth-handlers')
const AUTH_TOKENS = Symbol.for('auth-tokens')
const AUTH_SESSION = 'oidc'
const SESSION_COOKIE = 'session'
const ACCESS_TOKEN_COOKIE = 'access_token'
const REFRESH_TOKEN_COOKIE = 'refresh_token'
const ID_TOKEN_COOKIE = 'id_token'
const COOKIE_SERIALIZE_OPTIONS: CookieSerializeOptions = {
  path: '/',
  httpOnly: true,
  secure: false, // Set to true in production with HTTPS
  sameSite: 'lax'
}

type SessionValue = Record<string, unknown>

declare module 'fastify' {
  interface FastifyInstance {
    [AUTH_HANDLERS]: OpenIDAuthHandlers
  }

  interface FastifyRequest {
    [AUTH_TOKENS]?: Partial<TokenEndpointResponse>
  }
}

declare module '@fastify/secure-session' {
  interface SessionData {
    [AUTH_SESSION]?: SessionValue
  }
}

// Environment variables
const { OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, SESSION_KEY } =
  process.env

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET || !SESSION_KEY) {
  console.error('Missing required environment variables')
  process.exit(1)
}
// Type-safe environment variables after validation
const issuer = OIDC_ISSUER
const clientId = OIDC_CLIENT_ID
const clientSecret = OIDC_CLIENT_SECRET
const sessionKey = SESSION_KEY

const NotAuthenticatedError = createError(
  'FST_UNAUTHORIZED',
  'not authorized',
  401
)

const session: OpenIDSession<SessionValue> = {
  get(request, _reply) {
    request.log.trace(`Getting ${AUTH_SESSION} session variable`)
    return request.session.get(AUTH_SESSION)
  },
  set(request, _reply, value) {
    request.log.trace(
      `${value ? 'Setting' : 'Clearing'} ${AUTH_SESSION} session variable`
    )
    request.session.set(AUTH_SESSION, value)
  }
}

// Read tokens from cookies and session (unified logic)
const read: OpenIDReadTokens = (request, reply) => {
  // Check if tokenset is already attached to request
  const oldTokenset = request[AUTH_TOKENS]
  if (oldTokenset) {
    request.log.trace(
      oldTokenset,
      `Read tokenset from request[${String(AUTH_TOKENS)}]`
    )
    return oldTokenset
  }
  // Read from cookies and session (if available)
  const tokenset: Partial<TokenEndpointResponse> = {
    access_token: request.cookies[ACCESS_TOKEN_COOKIE],
    refresh_token: request.cookies[REFRESH_TOKEN_COOKIE],
    id_token: request.cookies[ID_TOKEN_COOKIE],
    ...session.get(request, reply)
  }
  request.log.trace(tokenset, 'Read tokenset from cookies/session')
  return tokenset
}

const write: OpenIDWriteTokens = (request, reply, tokenset) => {
  request.log.trace(tokenset, `Setting request[${String(AUTH_TOKENS)}]`)
  request[AUTH_TOKENS] = tokenset
  const { access_token, refresh_token, id_token, ...rest } = tokenset ?? {}
  if (access_token) {
    reply.log.trace({ access_token }, `Setting ${ACCESS_TOKEN_COOKIE} cookie`)
    reply.setCookie(ACCESS_TOKEN_COOKIE, access_token, COOKIE_SERIALIZE_OPTIONS)
  } else {
    reply.log.trace(`Clearing ${ACCESS_TOKEN_COOKIE} cookie`)
    reply.clearCookie(ACCESS_TOKEN_COOKIE, COOKIE_SERIALIZE_OPTIONS)
  }
  if (refresh_token) {
    reply.log.trace({ refresh_token }, `Setting ${REFRESH_TOKEN_COOKIE} cookie`)
    reply.setCookie(
      REFRESH_TOKEN_COOKIE,
      refresh_token,
      COOKIE_SERIALIZE_OPTIONS
    )
  } else {
    reply.log.trace(`Clearing ${REFRESH_TOKEN_COOKIE} cookie`)
    reply.clearCookie(REFRESH_TOKEN_COOKIE, COOKIE_SERIALIZE_OPTIONS)
  }
  if (id_token) {
    reply.log.trace({ id_token }, `Setting ${ID_TOKEN_COOKIE} cookie`)
    reply.setCookie(ID_TOKEN_COOKIE, id_token, COOKIE_SERIALIZE_OPTIONS)
  } else {
    reply.log.trace(`Clearing ${ID_TOKEN_COOKIE} cookie`)
    reply.clearCookie(ID_TOKEN_COOKIE, COOKIE_SERIALIZE_OPTIONS)
  }
  if (Object.keys(rest).length > 0) {
    session.set(request, reply, rest)
  } else {
    session.set(request, reply, undefined)
  }
}

async function main() {
  const fastify = Fastify({
    logger: {
      level: 'trace',
      transport: {
        target: 'pino-pretty'
      }
    }
  })

  // Register cookie plugin
  await fastify.register(cookie)

  // Register secure session plugin (required for OAuth state/nonce storage)
  await fastify.register(secureSession, {
    key: Buffer.from(sessionKey.padEnd(32, '0').slice(0, 32)),
    cookieName: SESSION_COOKIE,
    cookie: COOKIE_SERIALIZE_OPTIONS
  })

  // Discover OpenID configuration
  const config = await discovery(
    new URL(issuer),
    clientId,
    clientSecret,
    undefined,
    // NOTE: allowInsecureRequests is for local development only - remove in production!
    { execute: [allowInsecureRequests] }
  )

  // Get JWKS for token verification
  const jwksUri = config.serverMetadata().jwks_uri
  if (!jwksUri) {
    throw new Error('No JWKS URI found in OpenID configuration')
  }
  const key = createRemoteJWKSet(new URL(jwksUri))

  // Register OpenID auth plugin
  await fastify.register(openIDAuthPlugin, {
    decorator: AUTH_HANDLERS,
    config,
    login: {
      usePKCE: true,
      session,
      write,
      parameters: {
        redirect_uri: 'http://localhost:3000/login/callback',
        scope: 'openid profile email'
      }
    },
    verify: {
      key,
      tokens: ['id_token', 'access_token'],
      read,
      write(request, reply, tokenset, verified) {
        if (!verified?.access_token) {
          throw new NotAuthenticatedError()
        }
        return write.call(this, request, reply, tokenset, verified)
      }
    },
    refresh: {
      read,
      write
    },
    logout: {
      read,
      write(request, response) {
        return write.call(this, request, response)
      },
      parameters: {
        post_logout_redirect_uri: 'http://localhost:3000/logout/callback'
      }
    }
  })

  // Get auth handlers
  const { login, logout, verify, refresh } = fastify[AUTH_HANDLERS]

  // Routes
  fastify
    .get('/', (request) => {
      const hasToken = !!request.cookies[ACCESS_TOKEN_COOKIE]
      return hasToken
        ? {
            message: 'OpenID Connect Cookie Example (authenticated)',
            endpoints: {
              refresh: '/refresh',
              logout: '/logout',
              protected: '/protected'
            }
          }
        : {
            message: 'OpenID Connect Cookie Example (anonymous)',
            endpoints: {
              login: '/login',
              protected: '/protected'
            }
          }
    })
    .get('/login', login)
    .get('/login/callback', { preHandler: [login, verify] }, () => ({
      message: 'Login successful'
    }))
    .get('/refresh', { preHandler: [refresh, verify] }, () => ({
      message: 'Tokens refreshed'
    }))
    .get('/protected', { preHandler: verify }, () => ({
      message: 'You have access!'
    }))
    .get('/logout', logout)
    .get('/logout/callback', { preHandler: logout }, () => ({
      message: 'Logout successful'
    }))

  // Start server
  await fastify.listen({ port: 3000, host: '0.0.0.0' })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
