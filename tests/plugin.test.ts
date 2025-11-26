import { after, before, describe, it } from 'node:test'
import assert from 'node:assert'
import Fastify from 'fastify'
import type { Client } from 'openid-client'
import { createTestProvider, type TestProvider } from './fixtures/provider.ts'
import { getTestKeys } from './fixtures/keys.ts'
import { createTokenSet } from './fixtures/tokens.ts'
import { createTestClient } from './helpers/client.ts'
import { createMockSession } from './helpers/fastify.ts'
import plugin, { openIDAuthPlugin, type OpenIDAuthHandlers } from '../src/plugin.js'

describe('openIDAuthPlugin', () => {
  let provider: TestProvider
  let client: Client

  before(async () => {
    provider = await createTestProvider({ port: 3004 })
    client = await createTestClient({
      issuer: provider.issuer,
      clientId: 'test-client',
      clientSecret: 'test-secret'
    })
  })

  after(async () => {
    await provider.stop()
  })

  it('should register plugin and decorate fastify instance', async () => {
    const keys = await getTestKeys()
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const session = createMockSession()
    const fastify = Fastify({ logger: false })

    // Add session decorator
    fastify.decorateRequest('session', {
      getter() {
        return session
      }
    })

    await fastify.register(plugin, {
      decorator: 'openid',
      client,
      verify: {
        key: keys.publicKey,
        tokens: ['id_token'],
        options: {
          issuer: provider.issuer,
          audience: 'test-client'
        },
        read: () => tokenset
      },
      refresh: {
        read: () => tokenset
      },
      logout: {
        read: () => tokenset
      }
    })

    await fastify.ready()

    // Check that the decorator was added
    assert.ok((fastify as unknown as { openid: OpenIDAuthHandlers }).openid)
    const handlers = (fastify as unknown as { openid: OpenIDAuthHandlers }).openid
    assert.ok(typeof handlers.login === 'function')
    assert.ok(typeof handlers.verify === 'function')
    assert.ok(typeof handlers.refresh === 'function')
    assert.ok(typeof handlers.logout === 'function')

    await fastify.close()
  })

  it('should work with symbol decorator', async () => {
    const keys = await getTestKeys()
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const session = createMockSession()
    const fastify = Fastify({ logger: false })
    const decoratorSymbol = Symbol('openid')

    fastify.decorateRequest('session', {
      getter() {
        return session
      }
    })

    await fastify.register(plugin, {
      decorator: decoratorSymbol,
      client,
      verify: {
        key: keys.publicKey,
        tokens: ['id_token'],
        options: {
          issuer: provider.issuer,
          audience: 'test-client'
        },
        read: () => tokenset
      },
      refresh: {
        read: () => tokenset
      },
      logout: {
        read: () => tokenset
      }
    })

    await fastify.ready()

    // Check that the symbol decorator was added
    assert.ok((fastify as unknown as Record<symbol, OpenIDAuthHandlers>)[decoratorSymbol])

    await fastify.close()
  })

  it('should export openIDAuthPlugin function', () => {
    assert.ok(typeof openIDAuthPlugin === 'function')
  })

  it('should export default plugin', () => {
    assert.ok(typeof plugin === 'function')
    // fastify-plugin wraps the function with metadata
    assert.ok(plugin)
  })

  it('handlers should be usable in routes', async () => {
    const keys = await getTestKeys()
    const tokenset = await createTokenSet({
      issuer: provider.issuer,
      clientId: 'test-client'
    })

    const session = createMockSession()
    const fastify = Fastify({ logger: false })

    fastify.decorateRequest('session', {
      getter() {
        return session
      }
    })

    await fastify.register(plugin, {
      decorator: 'openid',
      client,
      verify: {
        key: keys.publicKey,
        tokens: ['id_token'],
        options: {
          issuer: provider.issuer,
          audience: 'test-client'
        },
        read: () => tokenset,
        write: async (_request, reply) => reply.send({ verified: true })
      },
      refresh: {
        read: () => tokenset
      },
      logout: {
        read: () => tokenset
      }
    })

    const openid = (fastify as unknown as { openid: OpenIDAuthHandlers }).openid

    fastify.get('/login', openid.login)
    fastify.get('/verify', openid.verify)
    fastify.get('/refresh', openid.refresh)
    fastify.get('/logout', openid.logout)

    await fastify.ready()

    // Test login route redirects
    const loginResponse = await fastify.inject({
      method: 'GET',
      url: '/login'
    })
    assert.strictEqual(loginResponse.statusCode, 302)

    // Test verify route
    const verifyResponse = await fastify.inject({
      method: 'GET',
      url: '/verify'
    })
    assert.strictEqual(verifyResponse.statusCode, 200)
    assert.deepStrictEqual(JSON.parse(verifyResponse.body), { verified: true })

    // Test logout route redirects
    const logoutResponse = await fastify.inject({
      method: 'GET',
      url: '/logout'
    })
    assert.strictEqual(logoutResponse.statusCode, 302)

    await fastify.close()
  })
})
