import assert from 'node:assert'
import { after, before, describe, it } from 'node:test'
import type { Configuration } from 'openid-client'
import { openIDLogoutHandlerFactory } from '../src/logout.js'
import { getTestKeys } from './fixtures/keys.ts'
import { createTestProvider, type TestProvider } from './fixtures/provider.ts'
import { createTokenSet } from './fixtures/tokens.ts'
import { createTestConfig } from './helpers/config.ts'
import { createTestFastify } from './helpers/fastify.ts'

describe('openIDLogoutHandlerFactory', () => {
  let provider: TestProvider
  let config: Configuration

  before(async () => {
    provider = await createTestProvider({ port: 3003 })
    config = await createTestConfig({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
  })

  after(async () => {
    await provider.stop()
  })

  describe('logout request', () => {
    it('should support dynamic end session parameters function', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      const handler = openIDLogoutHandlerFactory(config, {
        parameters: (request) => ({
          post_logout_redirect_uri:
            (request.query as { redirect?: string }).redirect ??
            'http://localhost:8080/default-logout'
        }),
        read: () => tokenset
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout?redirect=http://localhost:8080/custom-logout'
      })
      const location = response.headers.location as string
      assert.ok(
        location.includes(
          'post_logout_redirect_uri=' +
            encodeURIComponent('http://localhost:8080/custom-logout')
        )
      )
      await fastify.close()
    })

    it('should redirect to end session URL', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      const handler = openIDLogoutHandlerFactory(config, {
        read: () => tokenset
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      assert.strictEqual(response.statusCode, 302)
      const location = response.headers.location as string
      assert.ok(location.includes('/session/end'))
      assert.ok(location.includes('id_token_hint='))
      await fastify.close()
    })

    it('should include custom end session parameters', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      const handler = openIDLogoutHandlerFactory(config, {
        parameters: {
          post_logout_redirect_uri: 'http://localhost:8080/logged-out'
        },
        read: () => tokenset
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      const location = response.headers.location as string
      assert.ok(location.includes('post_logout_redirect_uri='))
      await fastify.close()
    })

    it('should call read function to get tokens', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      let readCalled = false
      const handler = openIDLogoutHandlerFactory(config, {
        read: () => {
          readCalled = true
          return tokenset
        }
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      assert.strictEqual(readCalled, true)
      await fastify.close()
    })
  })

  describe('logout callback', () => {
    it('should throw if post_logout_redirect_uri is not absolute', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      const handler = openIDLogoutHandlerFactory(config, {
        parameters: { post_logout_redirect_uri: '/relative/path' },
        read: () => tokenset
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      assert.strictEqual(response.statusCode, 500)
      assert.match(response.body, /ERR_INVALID_URL/)
      await fastify.close()
    })

    it('should call write function on callback', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      let writeCalled = false
      let receivedTokenset: unknown
      let receivedVerified: unknown
      const handler = openIDLogoutHandlerFactory(config, {
        parameters: {
          post_logout_redirect_uri:
            'http://localhost:8080/logout?state=some-state'
        },
        read: () => tokenset,
        write: async (_request, _reply, tokens, verified) => {
          writeCalled = true
          receivedTokenset = tokens
          receivedVerified = verified
        }
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      const _location = response.headers.location as string
      await fastify.inject({
        method: 'GET',
        url: '/logout?state=some-state'
      })
      assert.strictEqual(writeCalled, true)
      assert.ok(receivedTokenset)
      assert.ok(
        receivedVerified === undefined || typeof receivedVerified === 'object'
      )
      await fastify.close()
    })

    it('should verify tokens on callback when verify option provided', async () => {
      const keys = await getTestKeys()
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      let verifiedResult: unknown
      const handler = openIDLogoutHandlerFactory(config, {
        parameters: {
          post_logout_redirect_uri: 'http://localhost:8080/logout'
        },
        read: () => tokenset,
        verify: {
          key: keys.publicKey,
          tokens: ['id_token'],
          options: { issuer: provider.issuer, audience: 'test-client' }
        },
        write: async (_request, _reply, _tokens, verified) => {
          verifiedResult = verified
        }
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      assert.ok(verifiedResult)
      const verified = verifiedResult as { id_token?: unknown }
      assert.ok(verified.id_token)
      await fastify.close()
    })

    it('should work without write function on callback', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })
      const fastify = await createTestFastify()
      const handler = openIDLogoutHandlerFactory(config, {
        parameters: {
          post_logout_redirect_uri: 'http://localhost:8080/logout'
        },
        read: () => tokenset
      })
      fastify.get('/logout', handler)
      await fastify.ready()
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout'
      })
      assert.strictEqual(response.statusCode, 200)
      await fastify.close()
    })
  })
})
