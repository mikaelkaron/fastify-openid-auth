import { exportJWK, generateKeyPair } from 'jose'

export interface TestKeys {
  privateKey: CryptoKey
  publicKey: CryptoKey
  jwk: JsonWebKey & { kid: string; alg: string; use: string }
}

let cachedKeys: TestKeys | undefined

export async function getTestKeys(): Promise<TestKeys> {
  if (cachedKeys) {
    return cachedKeys
  }

  const { privateKey, publicKey } = await generateKeyPair('RS256')
  const jwk = await exportJWK(publicKey)

  cachedKeys = {
    privateKey,
    publicKey,
    jwk: {
      ...jwk,
      kid: 'test-key-1',
      alg: 'RS256',
      use: 'sig'
    }
  }

  return cachedKeys
}

export function getJWKS(keys: TestKeys) {
  return { keys: [keys.jwk] }
}
