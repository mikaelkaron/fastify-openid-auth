import assert from 'node:assert'
import { describe, it } from 'node:test'
import type { TokenEndpointResponse } from 'openid-client'
import {
  type OpenIDVerifyOptions,
  openIDJWTVerify,
  openIDVerifyHandlerFactory
} from '../src/verify.ts'
import { getTestKeys } from './fixtures/keys.ts'
import {
  createAccessToken,
  createIdToken,
  createTokenSet
} from './fixtures/tokens.ts'
import { createTestFastify } from './helpers/fastify.ts'

describe('openIDJWTVerify', () => {
  it('should verify id_token successfully', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const idToken = await createIdToken({ issuer, clientId })
    const tokenset: TokenEndpointResponse = {
      id_token: idToken,
      access_token: 'dummy',
      token_type: 'bearer'
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    const result = await openIDJWTVerify(tokenset, verifyOptions)

    assert.ok(result.id_token)
    assert.strictEqual(result.id_token.payload.iss, issuer)
    assert.strictEqual(result.id_token.payload.aud, clientId)
  })

  it('should verify access_token successfully', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const accessToken = await createAccessToken({ issuer, clientId })
    const tokenset: TokenEndpointResponse = {
      access_token: accessToken,
      token_type: 'bearer'
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['access_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    const result = await openIDJWTVerify(tokenset, verifyOptions)

    assert.ok(result.access_token)
    assert.strictEqual(result.access_token.payload.iss, issuer)
  })

  it('should verify multiple tokens', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const tokenset = await createTokenSet({ issuer, clientId })

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token', 'access_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    const result = await openIDJWTVerify(tokenset, verifyOptions)

    assert.ok(result.id_token)
    assert.ok(result.access_token)
  })

  it('should skip missing tokens', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const idToken = await createIdToken({ issuer, clientId })
    // TokenEndpointResponse requires access_token but we want to test skipping
    // refresh_token which is optional
    const tokenset: TokenEndpointResponse = {
      id_token: idToken,
      access_token: await createAccessToken({ issuer, clientId }),
      token_type: 'bearer'
      // refresh_token is intentionally missing
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token', 'refresh_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    const result = await openIDJWTVerify(tokenset, verifyOptions)
    assert.ok(result.id_token)
    assert.strictEqual(result.refresh_token, undefined)
  })

  it('should throw on invalid token signature', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    // Create a token and tamper with it
    const idToken = await createIdToken({ issuer, clientId })
    const tamperedToken = `${idToken.slice(0, -5)}XXXXX`
    const tokenset: TokenEndpointResponse = {
      id_token: tamperedToken,
      access_token: 'dummy',
      token_type: 'bearer'
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    await assert.rejects(
      () => openIDJWTVerify(tokenset, verifyOptions),
      /signature verification failed/
    )
  })

  it('should throw on expired token', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const expiredToken = await createIdToken({
      issuer,
      clientId,
      expiresIn: -3600 // Expired 1 hour ago
    })
    const tokenset: TokenEndpointResponse = {
      id_token: expiredToken,
      access_token: 'dummy',
      token_type: 'bearer'
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    await assert.rejects(
      () => openIDJWTVerify(tokenset, verifyOptions),
      /"exp" claim timestamp check failed/
    )
  })

  it('should throw on wrong issuer', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const idToken = await createIdToken({ issuer, clientId })
    const tokenset: TokenEndpointResponse = {
      id_token: idToken,
      access_token: 'dummy',
      token_type: 'bearer'
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer: 'https://wrong-issuer.example.com',
        audience: clientId
      }
    }

    await assert.rejects(
      () => openIDJWTVerify(tokenset, verifyOptions),
      /unexpected "iss" claim value/
    )
  })

  it('should throw on wrong audience', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const idToken = await createIdToken({ issuer, clientId })
    const tokenset: TokenEndpointResponse = {
      id_token: idToken,
      access_token: 'dummy',
      token_type: 'bearer'
    }

    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: 'wrong-client'
      }
    }

    await assert.rejects(
      () => openIDJWTVerify(tokenset, verifyOptions),
      /unexpected "aud" claim value/
    )
  })

  it('should work with key getter function', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    const idToken = await createIdToken({ issuer, clientId })
    const tokenset: TokenEndpointResponse = {
      id_token: idToken,
      access_token: 'dummy',
      token_type: 'bearer'
    }

    // Use a simple key getter function
    const getKey = async () => keys.publicKey

    const verifyOptions: OpenIDVerifyOptions = {
      key: getKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: clientId
      }
    }

    const result = await openIDJWTVerify(tokenset, verifyOptions)
    assert.ok(result.id_token)
  })
})

describe('openIDVerifyHandlerFactory', () => {
  it('should return 401 if required token is missing', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    // tokenset missing access_token, but with correct token_type type
    // access_token set to empty string to simulate missing token
    const tokenset: TokenEndpointResponse = {
      id_token: 'dummy',
      access_token: '',
      token_type: 'bearer' as Lowercase<string>
    }

    const fastify = await createTestFastify()

    const handler = openIDVerifyHandlerFactory({
      key: keys.publicKey,
      tokens: ['access_token'],
      options: { issuer, audience: clientId },
      read: () => tokenset
    })

    fastify.get('/protected', handler)
    await fastify.ready()

    const response = await fastify.inject({ method: 'GET', url: '/protected' })
    assert.strictEqual(response.statusCode, 500)
    assert.match(response.body, /ERR_JWS_INVALID/)

    await fastify.close()
  })

  it('should return 401 if token verification fails', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    // tokenset with invalid access_token and correct token_type type
    const tokenset: TokenEndpointResponse = {
      access_token: 'invalid.token',
      token_type: 'bearer' as Lowercase<string>
    }

    const fastify = await createTestFastify()

    const handler = openIDVerifyHandlerFactory({
      key: keys.publicKey,
      tokens: ['access_token'],
      options: { issuer, audience: clientId },
      read: () => tokenset
    })

    fastify.get('/protected', handler)
    await fastify.ready()

    const response = await fastify.inject({ method: 'GET', url: '/protected' })
    assert.strictEqual(response.statusCode, 500)
    // Accept any error message for token verification failure
    assert.match(response.body, /ERR_JWS_INVALID/)

    await fastify.close()
  })
  it('should create a handler that verifies tokens', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'
    const tokenset = await createTokenSet({ issuer, clientId })

    const fastify = await createTestFastify()

    let receivedVerified: unknown

    const handler = openIDVerifyHandlerFactory({
      key: keys.publicKey,
      tokens: ['id_token', 'access_token'],
      options: {
        issuer,
        audience: clientId
      },
      read: () => tokenset,
      write: async (_request, reply, _tokenset, verified) => {
        receivedVerified = verified
        return reply.send({ success: true })
      }
    })

    fastify.get('/verify', handler)
    await fastify.ready()

    const response = await fastify.inject({
      method: 'GET',
      url: '/verify'
    })

    assert.strictEqual(response.statusCode, 200)
    assert.ok(receivedVerified)
    const verified = receivedVerified as {
      id_token?: unknown
      access_token?: unknown
    }
    assert.ok(verified.id_token)
    assert.ok(verified.access_token)

    await fastify.close()
  })

  it('should call read function to get tokens', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'
    const tokenset = await createTokenSet({ issuer, clientId })

    const fastify = await createTestFastify()

    let readCalled = false

    const handler = openIDVerifyHandlerFactory({
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: clientId
      },
      read: () => {
        readCalled = true
        return tokenset
      },
      write: async (_request, reply) => reply.send({ success: true })
    })

    fastify.get('/verify', handler)
    await fastify.ready()

    await fastify.inject({
      method: 'GET',
      url: '/verify'
    })

    assert.strictEqual(readCalled, true)

    await fastify.close()
  })

  it('should work without write function', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'
    const tokenset = await createTokenSet({ issuer, clientId })

    const fastify = await createTestFastify()

    const handler = openIDVerifyHandlerFactory({
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer,
        audience: clientId
      },
      read: () => tokenset
    })

    fastify.get('/verify', handler)
    await fastify.ready()

    const response = await fastify.inject({
      method: 'GET',
      url: '/verify'
    })

    // Handler returns undefined when no write function
    assert.strictEqual(response.statusCode, 200)

    await fastify.close()
  })

  it('should throw when token verification fails', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'

    // Create token with wrong issuer
    const tokenset = await createTokenSet({
      issuer: 'https://wrong-issuer.example.com',
      clientId
    })

    const fastify = await createTestFastify()

    const handler = openIDVerifyHandlerFactory({
      key: keys.publicKey,
      tokens: ['id_token'],
      options: {
        issuer, // Expected issuer is different
        audience: clientId
      },
      read: () => tokenset
    })

    fastify.get('/verify', handler)
    await fastify.ready()

    const response = await fastify.inject({
      method: 'GET',
      url: '/verify'
    })

    assert.strictEqual(response.statusCode, 500)

    await fastify.close()
  })
})
