import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import { createRemoteJWKSet } from 'jose'
import openIDAuthPlugin, {
  discovery,
  type OpenIDAuthHandlers,
  type OpenIDReadTokens,
  type OpenIDWriteTokens,
  type TokenEndpointResponse
} from 'fastify-openid-auth'

// Environment variables
const { OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI } =
  process.env

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET || !OIDC_REDIRECT_URI) {
  console.error('Missing required environment variables')
  process.exit(1)
}

// Type-safe environment variables after validation
const issuer = OIDC_ISSUER
const clientId = OIDC_CLIENT_ID
const clientSecret = OIDC_CLIENT_SECRET
const redirectUri = OIDC_REDIRECT_URI

// Cookie names
const ACCESS_TOKEN_COOKIE = 'access_token'
const REFRESH_TOKEN_COOKIE = 'refresh_token'
const ID_TOKEN_COOKIE = 'id_token'

// Cookie options
const cookieOptions = {
  path: '/',
  httpOnly: true,
  secure: false, // Set to true in production with HTTPS
  sameSite: 'lax' as const
}

// Decorator symbol for auth handlers
const AUTH_HANDLERS = Symbol('auth-handlers')

declare module 'fastify' {
  interface FastifyInstance {
    [AUTH_HANDLERS]: OpenIDAuthHandlers
  }
}

// Read tokens from cookies
const read: OpenIDReadTokens = (request) => {
  const tokenset: TokenEndpointResponse = {
    access_token: request.cookies[ACCESS_TOKEN_COOKIE],
    refresh_token: request.cookies[REFRESH_TOKEN_COOKIE],
    id_token: request.cookies[ID_TOKEN_COOKIE]
  } as TokenEndpointResponse
  request.log.debug({ hasAccessToken: !!tokenset.access_token }, 'Read tokens from cookies')
  return tokenset
}

// Write tokens to cookies
const write: OpenIDWriteTokens = (_request, reply, tokenset) => {
  const { access_token, refresh_token, id_token } = tokenset

  if (access_token) {
    reply.setCookie(ACCESS_TOKEN_COOKIE, access_token, cookieOptions)
  } else {
    reply.clearCookie(ACCESS_TOKEN_COOKIE, cookieOptions)
  }

  if (refresh_token) {
    reply.setCookie(REFRESH_TOKEN_COOKIE, refresh_token, cookieOptions)
  } else {
    reply.clearCookie(REFRESH_TOKEN_COOKIE, cookieOptions)
  }

  if (id_token) {
    reply.setCookie(ID_TOKEN_COOKIE, id_token, cookieOptions)
  } else {
    reply.clearCookie(ID_TOKEN_COOKIE, cookieOptions)
  }
}

async function main() {
  const fastify = Fastify({
    logger: {
      level: 'debug',
      transport: {
        target: 'pino-pretty'
      }
    }
  })

  // Register cookie plugin
  await fastify.register(cookie)

  // Discover OpenID configuration
  const config = await discovery(new URL(issuer), clientId, clientSecret)

  // Get JWKS for token verification
  const jwksUri = config.serverMetadata().jwks_uri
  if (!jwksUri) {
    throw new Error('No JWKS URI found in OpenID configuration')
  }
  const jwks = createRemoteJWKSet(new URL(jwksUri))

  // Register OpenID auth plugin
  await fastify.register(openIDAuthPlugin, {
    decorator: AUTH_HANDLERS,
    config,
    login: {
      write,
      parameters: {
        redirect_uri: redirectUri,
        scope: 'openid profile email offline_access'
      }
    },
    verify: {
      key: jwks,
      tokens: ['id_token', 'access_token'],
      read,
      write
    },
    refresh: {
      read,
      write
    },
    logout: {
      read,
      write: (_request, reply) => {
        // Clear all token cookies on logout
        reply.clearCookie(ACCESS_TOKEN_COOKIE, cookieOptions)
        reply.clearCookie(REFRESH_TOKEN_COOKIE, cookieOptions)
        reply.clearCookie(ID_TOKEN_COOKIE, cookieOptions)
      },
      parameters: {
        post_logout_redirect_uri: 'http://localhost:3000/'
      }
    }
  })

  // Get auth handlers
  const { login, logout, verify, refresh } = fastify[AUTH_HANDLERS]

  // Routes
  fastify.get('/', async (request) => {
    const hasToken = !!request.cookies[ACCESS_TOKEN_COOKIE]
    if (hasToken) {
      return {
        message: 'You are logged in (tokens stored in cookies)',
        endpoints: { refresh: '/refresh', logout: '/logout', protected: '/protected' }
      }
    }
    return {
      message: 'You are not logged in',
      endpoints: { login: '/login' }
    }
  })

  fastify.get('/login', { preHandler: login }, async () => {
    // This handler won't be called - login redirects to IdP
  })

  fastify.get('/callback', { preHandler: [login, verify] }, async () => {
    return { message: 'Login successful' }
  })

  fastify.get('/refresh', { preHandler: [refresh, verify] }, async () => {
    return { message: 'Tokens refreshed' }
  })

  fastify.get('/logout', { preHandler: logout }, async () => {
    return { message: 'Logged out' }
  })

  fastify.get('/protected', { preHandler: verify }, async () => {
    return { message: 'You have access!' }
  })

  // Start server
  await fastify.listen({ port: 3000, host: '0.0.0.0' })
  console.log('Server running at http://localhost:3000')
  console.log('Login at http://localhost:3000/login')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
