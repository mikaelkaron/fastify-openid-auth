import { after, before, describe, it } from 'node:test'
import assert from 'node:assert'
import type { Client } from 'openid-client'
import { createTestProvider, type TestProvider } from './fixtures/provider.ts'
import { getTestKeys } from './fixtures/keys.ts'
import { createTokenSet, createExpiredTokenSet } from './fixtures/tokens.ts'
import { createTestClient } from './helpers/client.ts'
import { createTestFastify } from './helpers/fastify.ts'
import { openIDRefreshHandlerFactory } from '../src/refresh.js'

describe('openIDRefreshHandlerFactory', () => {
  let provider: TestProvider
  let client: Client

  before(async () => {
    provider = await createTestProvider({ port: 3002 })
    client = await createTestClient({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
  })

  after(async () => {
    await provider.stop()
  })

  it('should not refresh when token is not expired', async () => {
    const keys = await getTestKeys()
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const fastify = await createTestFastify()

    let writeCalled = false

    const handler = openIDRefreshHandlerFactory(client, {
      read: () => tokenset,
      write: async () => {
        writeCalled = true
      }
    })

    fastify.get('/refresh', handler)
    await fastify.ready()

    await fastify.inject({
      method: 'GET',
      url: '/refresh'
    })

    // Write should not be called for non-expired tokens
    assert.strictEqual(writeCalled, false)

    await fastify.close()
  })

  it('should attempt refresh when token is expired', async () => {
    const tokenset = await createExpiredTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const fastify = await createTestFastify()

    const handler = openIDRefreshHandlerFactory(client, {
      read: () => tokenset,
      write: async (_request, reply) => {
        return reply.send({ refreshed: true })
      }
    })

    fastify.get('/refresh', handler)
    await fastify.ready()

    // This will fail because the refresh_token is not valid for the provider
    // but it tests that the refresh attempt is made
    const response = await fastify.inject({
      method: 'GET',
      url: '/refresh'
    })

    // Should attempt refresh (and fail with invalid token)
    assert.strictEqual(response.statusCode, 500)

    await fastify.close()
  })

  it('should attempt refresh when expires_at is missing', async () => {
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    // Create tokenset without expires_at to trigger refresh
    const { expires_at: _, ...tokensetWithoutExpiry } = tokenset

    const fastify = await createTestFastify()

    const handler = openIDRefreshHandlerFactory(client, {
      read: () => tokensetWithoutExpiry,
      write: async (_request, reply) => {
        return reply.send({ refreshed: true })
      }
    })

    fastify.get('/refresh', handler)
    await fastify.ready()

    // This will fail because the refresh_token is not valid
    // but it tests that the refresh attempt is made when expires_at is missing
    const response = await fastify.inject({
      method: 'GET',
      url: '/refresh'
    })

    assert.strictEqual(response.statusCode, 500)

    await fastify.close()
  })

  it('should call read function to get tokens', async () => {
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const fastify = await createTestFastify()

    let readCalled = false

    const handler = openIDRefreshHandlerFactory(client, {
      read: () => {
        readCalled = true
        return tokenset
      }
    })

    fastify.get('/refresh', handler)
    await fastify.ready()

    await fastify.inject({
      method: 'GET',
      url: '/refresh'
    })

    assert.strictEqual(readCalled, true)

    await fastify.close()
  })

  it('should support verify option', async () => {
    const keys = await getTestKeys()
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const fastify = await createTestFastify()

    // Token is not expired, so verify won't be called
    // This just tests that the option is accepted
    const handler = openIDRefreshHandlerFactory(client, {
      read: () => tokenset,
      verify: {
        key: keys.publicKey,
        tokens: ['id_token'],
        options: {
          issuer: provider.issuer,
          audience: 'test-client'
        }
      }
    })

    fastify.get('/refresh', handler)
    await fastify.ready()

    const response = await fastify.inject({
      method: 'GET',
      url: '/refresh'
    })

    // Non-expired token, no refresh
    assert.strictEqual(response.statusCode, 200)

    await fastify.close()
  })
})
