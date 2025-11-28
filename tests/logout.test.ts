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
  let keys: Awaited<ReturnType<typeof getTestKeys>>

  before(async () => {
    provider = await createTestProvider({ port: 3003 })
    config = await createTestConfig({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
    keys = await getTestKeys()
  })

  after(async () => {
    await provider.stop()
  })

  describe('logout request', () => {
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
        parameters: {
          post_logout_redirect_uri: '/relative/path'
        },
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
        write: async (_request, reply, ts, verified) => {
          writeCalled = true
          receivedTokenset = ts
          receivedVerified = verified
          return reply.send({ loggedOut: true })
        }
      })

      fastify.get('/logout', handler)
      await fastify.ready()

      // Simulate callback with query params
      const response = await fastify.inject({
        method: 'GET',
        url: '/logout?state=some-state'
      })

      assert.strictEqual(response.statusCode, 200)
      assert.strictEqual(writeCalled, true)
      assert.ok(receivedTokenset)
      // receivedVerified may be undefined if verify is not provided
      assert.ok(
        receivedVerified === undefined || typeof receivedVerified === 'object'
      )

      await fastify.close()
    })

    it('should verify tokens on callback when verify option provided', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })

      const fastify = await createTestFastify()

      let receivedVerified: unknown

      const handler = openIDLogoutHandlerFactory(config, {
        parameters: {
          post_logout_redirect_uri:
            'http://localhost:8080/logout?state=some-state'
        },
        read: () => tokenset,
        verify: {
          key: keys.publicKey,
          tokens: ['id_token']
        },
        write: async (_request, reply, _ts, verified) => {
          receivedVerified = verified
          return reply.send({ loggedOut: true })
        }
      })

      fastify.get('/logout', handler)
      await fastify.ready()

      const response = await fastify.inject({
        method: 'GET',
        url: '/logout?state=some-state'
      })

      assert.strictEqual(response.statusCode, 200)
      assert.ok(receivedVerified)
      const verified = receivedVerified as { id_token?: unknown }
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
          post_logout_redirect_uri:
            'http://localhost:8080/logout?state=some-state'
        },
        read: () => tokenset
      })

      fastify.get('/logout', handler)
      await fastify.ready()

      const response = await fastify.inject({
        method: 'GET',
        url: '/logout?state=some-state'
      })

      // Handler returns undefined when no write function
      assert.strictEqual(response.statusCode, 200)

      await fastify.close()
    })
  })
})
