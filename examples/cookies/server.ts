import cookie from '@fastify/cookie'
import createError from '@fastify/error'
import secureSession from '@fastify/secure-session'
import Fastify from 'fastify'
import { createRemoteJWKSet } from 'jose'
import { allowInsecureRequests } from 'openid-client'
import openIDAuthPlugin, {
  discovery,
  type OpenIDAuthHandlers,
  type OpenIDReadTokens,
  type OpenIDTokens,
  type OpenIDWriteTokens,
  type TokenEndpointResponse
} from '../../src/index.ts'

const AUTH_HANDLERS = Symbol.for('auth-handlers')
const AUTH_TOKENS = Symbol.for('auth-tokens')

// Environment variables
const {
  OIDC_ISSUER,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  SESSION_KEY,
  ACCESS_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  ID_TOKEN_COOKIE
} = process.env

if (
  !OIDC_ISSUER ||
  !OIDC_CLIENT_ID ||
  !OIDC_CLIENT_SECRET ||
  !SESSION_KEY ||
  !ACCESS_TOKEN_COOKIE ||
  !REFRESH_TOKEN_COOKIE ||
  !ID_TOKEN_COOKIE
) {
  console.error('Missing required environment variables')
  process.exit(1)
}
// Type-safe environment variables after validation
const issuer = OIDC_ISSUER
const clientId = OIDC_CLIENT_ID
const clientSecret = OIDC_CLIENT_SECRET
const sessionKey = SESSION_KEY
const accessCookieName = ACCESS_TOKEN_COOKIE
const refreshCookieName = REFRESH_TOKEN_COOKIE
const idCookieName = ID_TOKEN_COOKIE

// Cookie options
const cookieOptions = {
  path: '/',
  httpOnly: true,
  secure: false, // Set to true in production with HTTPS
  sameSite: 'lax' as const
}

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
    [sessionKey]?: Omit<TokenEndpointResponse, OpenIDTokens>
  }
}

const NotAuthenticatedError = createError(
  'FST_UNAUTHORIZED',
  'not authorized',
  401
)

// Read tokens from cookies and session (unified logic)
const read: OpenIDReadTokens = (request) => {
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
    access_token: request.cookies[accessCookieName],
    refresh_token: request.cookies[refreshCookieName],
    id_token: request.cookies[idCookieName],
    ...request.session.get(sessionKey)
  }
  request.log.trace(tokenset, 'Read tokenset from cookies/session')
  return tokenset
}

const write: OpenIDWriteTokens = (request, reply, tokenset) => {
  request.log.trace(tokenset, `Setting request[${String(AUTH_TOKENS)}]`)
  request[AUTH_TOKENS] = tokenset
  const { access_token, refresh_token, id_token, ...rest } = tokenset ?? {}
  if (access_token) {
    reply.log.trace({ access_token }, `Setting ${accessCookieName} cookie`)
    reply.setCookie(accessCookieName, access_token, cookieOptions)
  } else {
    reply.log.trace(`Clearing ${accessCookieName} cookie`)
    reply.clearCookie(accessCookieName, cookieOptions)
  }
  if (refresh_token) {
    reply.log.trace({ refresh_token }, `Setting ${refreshCookieName} cookie`)
    reply.setCookie(refreshCookieName, refresh_token, cookieOptions)
  } else {
    reply.log.trace(`Clearing ${refreshCookieName} cookie`)
    reply.clearCookie(refreshCookieName, cookieOptions)
  }
  if (id_token) {
    reply.log.trace({ id_token }, `Setting ${idCookieName} cookie`)
    reply.setCookie(idCookieName, id_token, cookieOptions)
  } else {
    reply.log.trace(`Clearing ${idCookieName} cookie`)
    reply.clearCookie(idCookieName, cookieOptions)
  }
  if (Object.keys(rest).length > 0) {
    request.log.trace(rest, `Setting ${sessionKey} session variable`)
    request.session.set(sessionKey, rest)
  } else {
    request.log.trace(`Clearing ${sessionKey} session variable`)
    request.session.set(sessionKey, undefined)
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
    cookieName: 'session',
    cookie: {
      path: '/',
      httpOnly: true,
      secure: false, // Set to true in production with HTTPS
      sameSite: 'lax'
    }
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
        // Skip tokenset
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
      const hasToken = !!request.cookies[accessCookieName]
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
