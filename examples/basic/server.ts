import Fastify from 'fastify'
import { createRemoteJWKSet } from 'jose'
import openIDAuthPlugin, {
  discovery,
  type OpenIDAuthHandlers,
  type OpenIDReadTokens,
  type TokenEndpointResponse
} from '../../src/index.ts'

// Environment variables
const { OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI } =
  process.env

if (
  !OIDC_ISSUER ||
  !OIDC_CLIENT_ID ||
  !OIDC_CLIENT_SECRET ||
  !OIDC_REDIRECT_URI
) {
  console.error('Missing required environment variables')
  process.exit(1)
}

// Type-safe environment variables after validation
const issuer = OIDC_ISSUER
const clientId = OIDC_CLIENT_ID
const clientSecret = OIDC_CLIENT_SECRET
const redirectUri = OIDC_REDIRECT_URI

// Decorator symbol for auth handlers
const AUTH_HANDLERS = Symbol('auth-handlers')

declare module 'fastify' {
  interface FastifyInstance {
    [AUTH_HANDLERS]: OpenIDAuthHandlers
  }
}

// Read access token from Authorization: Bearer header
const read: OpenIDReadTokens = (request) => {
  const authHeader = request.headers.authorization
  if (authHeader?.startsWith('Bearer ')) {
    const accessToken = authHeader.slice(7)
    request.log.debug('Read access token from Authorization header')
    return { access_token: accessToken } as TokenEndpointResponse
  }
  return {} as TokenEndpointResponse
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
      // Return tokens as JSON after successful login
      write: async (_request, reply, tokenset) => {
        return reply.send({
          access_token: tokenset.access_token,
          token_type: tokenset.token_type,
          expires_in: tokenset.expires_in,
          refresh_token: tokenset.refresh_token,
          scope: tokenset.scope
        })
      },
      parameters: {
        redirect_uri: redirectUri,
        scope: 'openid profile email offline_access'
      }
    },
    verify: {
      key: jwks,
      tokens: ['access_token'],
      read
    },
    refresh: {
      read,
      // Return new tokens as JSON after refresh
      write: async (_request, reply, tokenset) => {
        return reply.send({
          access_token: tokenset.access_token,
          token_type: tokenset.token_type,
          expires_in: tokenset.expires_in,
          refresh_token: tokenset.refresh_token,
          scope: tokenset.scope
        })
      }
    },
    logout: {
      read,
      parameters: {
        post_logout_redirect_uri: 'http://localhost:3000/'
      }
    }
  })

  // Get auth handlers
  const { login, logout, verify, refresh } = fastify[AUTH_HANDLERS]

  // Routes
  fastify.get('/', async () => {
    return {
      message: 'OpenID Connect Basic Example',
      description: 'Use Bearer token authentication for protected routes',
      endpoints: {
        login: 'GET /login - Redirects to IdP, returns tokens as JSON',
        callback: 'GET /callback - OAuth callback (handled automatically)',
        protected:
          'GET /protected - Requires Authorization: Bearer <access_token>',
        refresh: 'POST /refresh - Refresh tokens (send refresh_token in body)',
        logout: 'GET /logout - End session'
      }
    }
  })

  fastify.get('/login', { preHandler: login }, async () => {
    // This handler won't be called - login redirects to IdP
  })

  fastify.get('/callback', { preHandler: login }, async () => {
    // This handler won't be called - login.write sends the response
  })

  fastify.get('/protected', { preHandler: verify }, async () => {
    return {
      message: 'You have access!',
      note: 'Token was verified successfully'
    }
  })

  fastify.post('/refresh', { preHandler: refresh }, async () => {
    // This handler won't be called - refresh.write sends the response
  })

  fastify.get('/logout', { preHandler: logout }, async () => {
    return { message: 'Logged out' }
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
