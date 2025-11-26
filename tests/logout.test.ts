import { after, before, describe, it } from 'node:test'
import assert from 'node:assert'
import type { Client } from 'openid-client'
import { createTestProvider, type TestProvider } from './fixtures/provider.ts'
import { getTestKeys } from './fixtures/keys.ts'
import { createTokenSet } from './fixtures/tokens.ts'
import { createTestClient } from './helpers/client.ts'
import { createTestFastify } from './helpers/fastify.ts'
import { openIDLogoutHandlerFactory } from '../src/logout.js'

describe('openIDLogoutHandlerFactory', () => {
  let provider: TestProvider
  let client: Client

  before(async () => {
    provider = await createTestProvider({ port: 3003 })
    client = await createTestClient({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
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

      const handler = openIDLogoutHandlerFactory(client, {
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

      const handler = openIDLogoutHandlerFactory(client, {
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

      const handler = openIDLogoutHandlerFactory(client, {
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
    it('should call write function on callback', async () => {
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })

      const fastify = await createTestFastify()

      let writeCalled = false
      let receivedTokenset: unknown

      const handler = openIDLogoutHandlerFactory(client, {
        read: () => tokenset,
        write: async (_request, reply, ts) => {
          writeCalled = true
          receivedTokenset = ts
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

      await fastify.close()
    })

    it('should verify tokens on callback when verify option provided', async () => {
      const keys = await getTestKeys()
      const tokenset = await createTokenSet({
        issuer: provider.issuer,
        clientId: 'test-client'
      })

      const fastify = await createTestFastify()

      let receivedVerified: unknown

      const handler = openIDLogoutHandlerFactory(client, {
        read: () => tokenset,
        verify: {
          key: keys.publicKey,
          tokens: ['id_token'],
          options: {
            issuer: provider.issuer,
            audience: 'test-client'
          }
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

      const handler = openIDLogoutHandlerFactory(client, {
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
