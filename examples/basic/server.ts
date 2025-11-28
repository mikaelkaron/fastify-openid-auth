import createError from '@fastify/error'
import secureSession from '@fastify/secure-session'
import Fastify from 'fastify'
import { createRemoteJWKSet } from 'jose'
import {
  allowInsecureRequests,
  type TokenEndpointResponse
} from 'openid-client'
import openIDAuthPlugin, {
  discovery,
  type OpenIDAuthHandlers,
  type OpenIDReadTokens,
  type OpenIDWriteTokens
} from '../../src/index.ts'

const AUTH_HANDLERS = Symbol.for('auth-handlers')
const AUTH_TOKENS = Symbol.for('auth-tokens')

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

declare module 'fastify' {
  interface FastifyInstance {
    [AUTH_HANDLERS]: OpenIDAuthHandlers
  }

  interface FastifyRequest {
    [AUTH_TOKENS]?: Partial<TokenEndpointResponse>
  }
}

const NotAuthenticatedError = createError(
  'FST_UNAUTHORIZED',
  'not authorized',
  401
)

// Read access token from Authorization: Bearer header
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
  const authHeader = request.headers.authorization
  if (authHeader?.startsWith('Bearer ')) {
    request.log.debug('Read access token from Authorization header')
    const access_token = authHeader.slice(7)
    return { access_token }
  }
  return {}
}

const write: OpenIDWriteTokens = async (request, _reply, tokenset) => {
  request.log.trace(tokenset, `Setting request[${String(AUTH_TOKENS)}]`)
  request[AUTH_TOKENS] = tokenset
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
      tokens: ['access_token'],
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
      parameters: {
        post_logout_redirect_uri: 'http://localhost:3000/logout/callback'
      }
    }
  })

  // Get auth handlers
  const { login, logout, verify, refresh } = fastify[AUTH_HANDLERS]

  // Routes
  fastify
    .get('/', () => {
      return {
        message: 'OpenID Connect Basic Example',
        endpoints: {
          login: '/login',
          refresh: '/refresh',
          logout: '/logout',
          protected: '/protected'
        }
      }
    })
    .get('/login', login)
    .get('/login/callback', { preHandler: [login, verify] }, (request) => ({
      message: 'Login successful',
      tokens: request[AUTH_TOKENS]
    }))
    .get('/refresh', { preHandler: [refresh, verify] }, (request) => ({
      message: 'Tokens refreshed',
      tokens: request[AUTH_TOKENS]
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
