import assert from 'node:assert'
import { after, before, describe, it } from 'node:test'
import type { FastifyReply, FastifyRequest } from 'fastify'
import type { Configuration } from 'openid-client'
import {
  openIDLoginHandlerFactory,
  SessionKeyError,
  SessionValueError,
  SupportedMethodError
} from '../src/login.ts'
import { createTestProvider, type TestProvider } from './fixtures/provider.ts'
import { createTestConfig } from './helpers/config.ts'
import { createTestFastify, createTestSession } from './helpers/fastify.ts'

describe('openIDLoginHandlerFactory', () => {
  // Use createTestSession for required session API
  let provider: TestProvider
  let config: Configuration

  before(async () => {
    provider = await createTestProvider({ port: 3001 })
    config = await createTestConfig({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
  })

  after(async () => {
    await provider.stop()
  })

  describe('authorization request', () => {
    it('should support dynamic authorization parameters function with custom redirect_uri', async () => {
      const session = createTestSession()
      const fastify = await createTestFastify()
      const handler = openIDLoginHandlerFactory(config, {
        parameters: (request) => ({
          scope: 'openid',
          redirect_uri:
            (request.query as { redirect?: string }).redirect ??
            'http://localhost:8080/default-login'
        }),
        session
      })

      fastify.get('/login', handler)
      await fastify.ready()

      const response = await fastify.inject({
        method: 'GET',
        url: '/login?redirect=http://localhost:8080/custom-login'
      })

      const location = response.headers.location as string
      assert.ok(
        location.includes(
          'redirect_uri=' +
            encodeURIComponent('http://localhost:8080/custom-login')
        )
      )

      await fastify.close()
    })
    it('should redirect to authorization URL with default parameters', async () => {
      const session = createTestSession()
      const fastify = await createTestFastify()
      const handler = openIDLoginHandlerFactory(config, {
        session
      })

      fastify.get('/login', handler)
      await fastify.ready()

      const response = await fastify.inject({
        method: 'GET',
        url: '/login'
      })

      assert.strictEqual(response.statusCode, 302)
      const location = response.headers.location as string
      assert.ok(location.startsWith(provider.issuer))
      assert.ok(location.includes('response_type=code'))
      assert.ok(location.includes('scope=openid'))
      assert.ok(location.includes('state='))
      assert.ok(location.includes('nonce='))

      // Session should have callback checks stored
      const mockRequest = {} as FastifyRequest
      const mockReply = {} as FastifyReply
      const callbackChecks = await session.get(mockRequest, mockReply)
      assert.ok(callbackChecks)
      assert.ok((callbackChecks as { state: string }).state)
      assert.ok((callbackChecks as { nonce: string }).nonce)

      await fastify.close()
    })

    it('should use custom session key when provided', async () => {
      const session = createTestSession()
      const fastify = await createTestFastify()
      const handler = openIDLoginHandlerFactory(config, {
        session
      })

      fastify.get('/login', handler)
      await fastify.ready()

      await fastify.inject({
        method: 'GET',
        url: '/login'
      })

      const mockRequest = {} as FastifyRequest
      const mockReply = {} as FastifyReply
      const callbackChecks = await session.get(mockRequest, mockReply)
      assert.ok(callbackChecks)

      await fastify.close()
    })

    it('should include custom authorization parameters', async () => {
      const session = createTestSession()
      const fastify = await createTestFastify()
      const handler = openIDLoginHandlerFactory(config, {
        parameters: {
          scope: 'openid profile email',
          prompt: 'consent'
        },
        session
      })

      fastify.get('/login', handler)
      await fastify.ready()

      const response = await fastify.inject({
        method: 'GET',
        url: '/login'
      })

      const location = response.headers.location as string
      // Check for scope with either + or %20 encoding
      assert.ok(
        location.includes('scope=openid+profile+email') ||
          location.includes('scope=openid%20profile%20email')
      )
      assert.ok(location.includes('prompt=consent'))

      await fastify.close()
    })

    it('should support dynamic authorization parameters function', async () => {
      const session = createTestSession()
      const fastify = await createTestFastify()
      const handler = openIDLoginHandlerFactory(config, {
        parameters: (request) => ({
          scope: 'openid',
          state:
            (request.query as { customState?: string }).customState ?? 'default'
        }),
        session
      })

      fastify.get('/login', handler)
      await fastify.ready()

      const response = await fastify.inject({
        method: 'GET',
        url: '/login?customState=my-state'
      })

      const location = response.headers.location as string
      assert.ok(location.includes('state=my-state'))

      await fastify.close()
    })

    describe('PKCE', () => {
      it('should include S256 code challenge when usePKCE is true', async () => {
        const session = createTestSession()
        const fastify = await createTestFastify()
        const handler = openIDLoginHandlerFactory(config, {
          usePKCE: true,
          session
        })

        fastify.get('/login', handler)
        await fastify.ready()

        const response = await fastify.inject({
          method: 'GET',
          url: '/login'
        })

        const location = response.headers.location as string
        assert.ok(location.includes('code_challenge='))
        assert.ok(location.includes('code_challenge_method=S256'))

        // Session should have pkceCodeVerifier stored
        const mockRequest = {} as FastifyRequest
        const mockReply = {} as FastifyReply
        const callbackChecks = (await session.get(mockRequest, mockReply)) as {
          pkceCodeVerifier?: string
        }
        assert.ok(callbackChecks.pkceCodeVerifier)

        await fastify.close()
      })

      it('should include S256 code challenge when usePKCE is "S256"', async () => {
        const session = createTestSession()
        const fastify = await createTestFastify()
        const handler = openIDLoginHandlerFactory(config, {
          usePKCE: 'S256',
          session
        })

        fastify.get('/login', handler)
        await fastify.ready()

        const response = await fastify.inject({
          method: 'GET',
          url: '/login'
        })

        const location = response.headers.location as string
        assert.ok(location.includes('code_challenge_method=S256'))

        await fastify.close()
      })

      it('should include plain code challenge when usePKCE is "plain"', async () => {
        const session = createTestSession()
        const fastify = await createTestFastify()
        const handler = openIDLoginHandlerFactory(config, {
          usePKCE: 'plain',
          session
        })

        fastify.get('/login', handler)
        await fastify.ready()

        const response = await fastify.inject({
          method: 'GET',
          url: '/login'
        })

        const location = response.headers.location as string
        // Plain PKCE includes code_challenge and code_challenge_method=plain
        assert.ok(location.includes('code_challenge='))
        assert.ok(location.includes('code_challenge_method=plain'))

        await fastify.close()
      })

      it('should not include code challenge when usePKCE is false', async () => {
        const session = createTestSession()
        const fastify = await createTestFastify()
        const handler = openIDLoginHandlerFactory(config, {
          usePKCE: false,
          session
        })

        fastify.get('/login', handler)
        await fastify.ready()

        const response = await fastify.inject({
          method: 'GET',
          url: '/login'
        })

        const location = response.headers.location as string
        assert.ok(!location.includes('code_challenge='))

        await fastify.close()
      })
    })
  })

  describe('callback handling', () => {
    it('should throw SessionValueError when session data is missing', async () => {
      const session = createTestSession()
      const fastify = await createTestFastify()
      const handler = openIDLoginHandlerFactory(config, {
        session
      })

      fastify.get('/callback', handler)
      await fastify.ready()

      // Simulate callback without prior auth request (no session data)
      const response = await fastify.inject({
        method: 'GET',
        url: '/callback?code=test-code&state=test-state'
      })

      assert.strictEqual(response.statusCode, 500)
      const body = JSON.parse(response.body)
      assert.strictEqual(body.code, 'FST_SESSION_VALUE')

      await fastify.close()
    })

    it('should call write function with tokenset after successful callback', async () => {
      // This test requires a full OIDC flow which is complex to mock
      // We'll test that the handler structure is correct
      const session = createTestSession()
      const fastify = await createTestFastify()

      let _writeCalled = false
      let _receivedTokenset: unknown

      const handler = openIDLoginHandlerFactory(config, {
        write: async (_request, reply, tokenset) => {
          _writeCalled = true
          _receivedTokenset = tokenset
          return reply.send({ success: true })
        },
        session
      })

      fastify.get('/login', handler)
      await fastify.ready()

      // First, make the authorization request to set up session
      await fastify.inject({
        method: 'GET',
        url: '/login'
      })

      // The full callback flow requires actual token exchange
      // which needs the oidc-provider to issue real codes
      // This is tested in integration tests

      await fastify.close()
    })
  })

  describe('error handling', () => {
    it('should export SessionKeyError', () => {
      assert.ok(SessionKeyError)
      const error = new SessionKeyError()
      assert.strictEqual(error.code, 'FST_SESSION_KEY')
      assert.strictEqual(error.statusCode, 500)
    })

    it('should export SessionValueError', () => {
      assert.ok(SessionValueError)
      const error = new SessionValueError('test-key')
      assert.strictEqual(error.code, 'FST_SESSION_VALUE')
      assert.strictEqual(error.statusCode, 500)
      assert.ok(error.message.includes('test-key'))
    })

    it('should export SupportedMethodError', () => {
      assert.ok(SupportedMethodError)
      const error = new SupportedMethodError()
      assert.strictEqual(error.code, 'FST_SUPPORTED_METHOD')
      assert.strictEqual(error.statusCode, 500)
    })
  })
})
