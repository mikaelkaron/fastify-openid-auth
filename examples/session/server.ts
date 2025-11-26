import Fastify from 'fastify'
import secureSession from '@fastify/secure-session'
import { createRemoteJWKSet } from 'jose'
import openIDAuthPlugin, {
  discovery,
  type OpenIDAuthHandlers,
  type OpenIDReadTokens,
  type OpenIDWriteTokens,
  type TokenEndpointResponse
} from 'fastify-openid-auth'

// Environment variables
const { OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI, SESSION_KEY } =
  process.env

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET || !OIDC_REDIRECT_URI || !SESSION_KEY) {
  console.error('Missing required environment variables')
  process.exit(1)
}

// Type-safe environment variables after validation
const issuer = OIDC_ISSUER
const clientId = OIDC_CLIENT_ID
const clientSecret = OIDC_CLIENT_SECRET
const redirectUri = OIDC_REDIRECT_URI
const sessionKey = SESSION_KEY

// Session data key for tokens
const TOKENS_KEY = 'tokens'

// Decorator symbol for auth handlers
const AUTH_HANDLERS = Symbol('auth-handlers')

declare module 'fastify' {
  interface FastifyInstance {
    [AUTH_HANDLERS]: OpenIDAuthHandlers
  }
}

declare module '@fastify/secure-session' {
  interface SessionData {
    [TOKENS_KEY]?: TokenEndpointResponse
  }
}

// Read tokens from secure session
const read: OpenIDReadTokens = (request) => {
  const tokens = request.session.get(TOKENS_KEY)
  request.log.debug({ hasTokens: !!tokens }, 'Read tokens from session')
  return tokens ?? ({} as TokenEndpointResponse)
}

// Write tokens to secure session
const write: OpenIDWriteTokens = (request, _reply, tokenset) => {
  request.log.debug({ hasTokens: Object.keys(tokenset).length > 0 }, 'Writing tokens to session')
  if (Object.keys(tokenset).length > 0) {
    request.session.set(TOKENS_KEY, tokenset)
  } else {
    request.session.delete()
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

  // Register secure session plugin (encrypted session cookie)
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
      write: (request, _reply) => {
        // Clear session on logout
        request.session.delete()
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
    const tokens = request.session.get(TOKENS_KEY)
    if (tokens?.id_token) {
      return {
        message: 'You are logged in (tokens stored in encrypted session)',
        tokens: formatTokens(tokens),
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

  fastify.get('/callback', { preHandler: [login, verify] }, async (request) => {
    const tokens = request.session.get(TOKENS_KEY)
    return { message: 'Login successful', tokens: tokens && formatTokens(tokens) }
  })

  fastify.get('/refresh', { preHandler: [refresh, verify] }, async (request) => {
    const tokens = request.session.get(TOKENS_KEY)
    return { message: 'Tokens refreshed', tokens: tokens && formatTokens(tokens) }
  })

  fastify.get('/logout', { preHandler: logout }, async () => {
    return { message: 'Logged out' }
  })

  fastify.get('/protected', { preHandler: verify }, async (request) => {
    const tokens = request.session.get(TOKENS_KEY)
    return { message: 'You have access!', tokens: tokens && formatTokens(tokens) }
  })

  // Start server
  await fastify.listen({ port: 3000, host: '0.0.0.0' })
  console.log('Server running at http://localhost:3000')
  console.log('Login at http://localhost:3000/login')
}

// Format tokens for display (hide sensitive parts)
function formatTokens(tokenset: TokenEndpointResponse) {
  return {
    token_type: tokenset.token_type,
    expires_in: tokenset.expires_in,
    scope: tokenset.scope,
    has_access_token: !!tokenset.access_token,
    has_id_token: !!tokenset.id_token,
    has_refresh_token: !!tokenset.refresh_token
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
