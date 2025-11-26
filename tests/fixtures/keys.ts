import {
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  type KeyObject
} from 'jose'

export interface TestKeys {
  privateKey: CryptoKey | KeyObject
  publicKey: CryptoKey | KeyObject
  privateJwk: JsonWebKey & { kid: string; alg: string; use: string }
  publicJwk: JsonWebKey & { kid: string; alg: string; use: string }
}

let cachedKeys: TestKeys | undefined

export async function getTestKeys(): Promise<TestKeys> {
  if (cachedKeys) {
    return cachedKeys
  }

  const { privateKey, publicKey } = await generateKeyPair('RS256', {
    extractable: true
  })
  const privateJwk = await exportJWK(privateKey)
  const publicJwk = await exportJWK(publicKey)

  const keys: TestKeys = {
    privateKey,
    publicKey,
    privateJwk: {
      ...privateJwk,
      kid: 'test-key-1',
      alg: 'RS256',
      use: 'sig'
    },
    publicJwk: {
      ...publicJwk,
      kid: 'test-key-1',
      alg: 'RS256',
      use: 'sig'
    }
  }

  cachedKeys = keys
  return keys
}

export function getPrivateJWKS(keys: TestKeys) {
  return { keys: [keys.privateJwk] }
}

export function getPublicJWKS(keys: TestKeys) {
  return { keys: [keys.publicJwk] }
}
