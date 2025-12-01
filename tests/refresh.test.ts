import assert from 'node:assert'
import { after, before, describe, it } from 'node:test'
import type { Next, ParameterizedContext } from 'koa'
import bodyParser from 'koa-bodyparser'
import type { Configuration } from 'openid-client'
import { openIDRefreshHandlerFactory } from '../src/refresh.js'
import { getTestKeys } from './fixtures/keys.ts'
import { createTestProvider, type TestProvider } from './fixtures/provider.ts'
import { createExpiredTokenSet, createTokenSet } from './fixtures/tokens.ts'
import { createTestConfig } from './helpers/config.ts'
import { createTestFastify } from './helpers/fastify.ts'

describe('openIDRefreshHandlerFactory', () => {
  let provider: TestProvider
  let config: Configuration

  before(async () => {
    provider = await createTestProvider({ port: 3002 })
    config = await createTestConfig({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
  })

  after(async () => {
    await provider.stop()
  })

  it('should not refresh when token is not expired', async () => {
    const _keys = await getTestKeys()
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })
    const fastify = await createTestFastify()
    let writeCalled = false
    const handler = openIDRefreshHandlerFactory(config, {
      read: () => tokenset,
      write: async () => {
        writeCalled = true
      }
    })
    fastify.get('/refresh', handler)
    await fastify.ready()
    await fastify.inject({ method: 'GET', url: '/refresh' })
    assert.strictEqual(writeCalled, false)
    await fastify.close()
  })

  it('should attempt refresh when token is expired', async () => {
    const tokenset = await createExpiredTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })
    const fastify = await createTestFastify()
    const handler = openIDRefreshHandlerFactory(config, {
      read: () => tokenset,
      write: async (_request, reply) => {
        return reply.send({ refreshed: true })
      }
    })
    fastify.get('/refresh', handler)
    await fastify.ready()
    const response = await fastify.inject({ method: 'GET', url: '/refresh' })
    assert.ok(
      response.statusCode === 400 || response.statusCode === 500,
      `Expected 400 or 500, got ${response.statusCode}`
    )
    await fastify.close()
  })

  it('should attempt refresh when expires_at is missing', async () => {
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })
    const { expires_at: _, ...tokensetWithoutExpiry } = tokenset
    const fastify = await createTestFastify()
    const handler = openIDRefreshHandlerFactory(config, {
      read: () => tokensetWithoutExpiry,
      write: async (_request, reply) => {
        return reply.send({ refreshed: true })
      }
    })
    fastify.get('/refresh', handler)
    await fastify.ready()
    const response = await fastify.inject({ method: 'GET', url: '/refresh' })
    assert.ok(
      response.statusCode === 400 || response.statusCode === 500,
      `Expected 400 or 500, got ${response.statusCode}`
    )
    await fastify.close()
  })

  it('should call read function to get tokens', async () => {
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })
    const fastify = await createTestFastify()
    let readCalled = false
    const handler = openIDRefreshHandlerFactory(config, {
      read: () => {
        readCalled = true
        return tokenset
      }
    })
    fastify.get('/refresh', handler)
    await fastify.ready()
    await fastify.inject({ method: 'GET', url: '/refresh' })
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
    const handler = openIDRefreshHandlerFactory(config, {
      read: () => tokenset,
      verify: {
        key: keys.publicKey,
        tokens: ['id_token'],
        options: { issuer: provider.issuer, audience: 'test-client' }
      }
    })
    fastify.get('/refresh', handler)
    await fastify.ready()
    const response = await fastify.inject({ method: 'GET', url: '/refresh' })
    assert.strictEqual(response.statusCode, 200)
    await fastify.close()
  })

  it('should support dynamic refresh parameters function', async () => {
    const tokenset = await createExpiredTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })
    const fastify = await createTestFastify()
    let lastTokenRequestBody: unknown = null
    // Add bodyParser middleware before captureMiddleware for this test
    provider.testMiddleware.add(bodyParser())
    const captureMiddleware = async (ctx: ParameterizedContext, next: Next) => {
      if (ctx.path === '/token' && ctx.method === 'POST') {
        if (typeof ctx.request.body === 'string') {
          try {
            lastTokenRequestBody = JSON.parse(ctx.request.body)
          } catch {
            lastTokenRequestBody = ctx.request.body
          }
        } else {
          lastTokenRequestBody = ctx.request.body
        }
      }
      await next()
    }
    provider.testMiddleware.add(captureMiddleware)
    const handler = openIDRefreshHandlerFactory(config, {
      tokenEndpoint: {
        parameters: (request) => ({
          custom: (request.query as { custom?: string }).custom ?? 'default'
        })
      },
      read: () => tokenset
    })
    fastify.get('/refresh', handler)
    await fastify.ready()
    await fastify.inject({ method: 'GET', url: '/refresh?custom=bar' })
    // Remove the test-specific middleware after the test
    provider.testMiddleware.remove(captureMiddleware)
    assert.ok(lastTokenRequestBody)
    if (
      typeof lastTokenRequestBody === 'object' &&
      lastTokenRequestBody !== null &&
      'custom' in lastTokenRequestBody
    ) {
      assert.strictEqual(
        (lastTokenRequestBody as { custom: string }).custom,
        'bar'
      )
    } else {
      assert.fail('lastTokenRequestBody does not have a custom property')
    }
    await fastify.close()
  })
})
