import assert from 'node:assert'
import { describe, it } from 'node:test'
import type { TokenEndpointResponse } from 'openid-client'
import { type OpenIDVerifyOptions, openIDJWTVerify } from '../src/verify.ts'
import { getTestKeys } from './fixtures/keys.ts'
import {
  createAccessToken,
  createIdToken,
  createTokenSet
} from './fixtures/tokens.ts'

describe('openIDJWTVerify and Factories (unit)', () => {
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
      options: { issuer, audience: clientId }
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
      options: { issuer, audience: clientId }
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
      options: { issuer, audience: clientId }
    }
    const result = await openIDJWTVerify(tokenset, verifyOptions)
    assert.ok(result.id_token)
    assert.ok(result.access_token)
    assert.strictEqual(result.id_token.payload.iss, issuer)
  })

  it('should skip missing tokens', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'
    const idToken = await createIdToken({ issuer, clientId })
    const tokenset: TokenEndpointResponse = {
      id_token: idToken,
      access_token: await createAccessToken({ issuer, clientId }),
      token_type: 'bearer'
    }
    const verifyOptions: OpenIDVerifyOptions = {
      key: keys.publicKey,
      tokens: ['id_token', 'refresh_token'],
      options: { issuer, audience: clientId }
    }
    const result = await openIDJWTVerify(tokenset, verifyOptions)
    assert.ok(result.id_token)
    assert.strictEqual(result.refresh_token, undefined)
  })

  it('should throw on invalid token signature', async () => {
    const keys = await getTestKeys()
    const issuer = 'https://test-issuer.example.com'
    const clientId = 'test-client'
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
      options: { issuer, audience: clientId }
    }
    await assert.rejects(
      () => openIDJWTVerify(tokenset, verifyOptions),
      /signature verification failed/
    )
  })
})
