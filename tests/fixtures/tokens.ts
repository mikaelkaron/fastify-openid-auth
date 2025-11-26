import { SignJWT } from 'jose'
import type { TokenSetParameters } from 'openid-client'
import { getTestKeys } from './keys.ts'

export interface CreateTokenOptions {
  issuer: string
  clientId: string
  subject?: string
  expiresIn?: number
  nonce?: string
}

export async function createIdToken(
  options: CreateTokenOptions
): Promise<string> {
  const keys = await getTestKeys()
  const now = Math.floor(Date.now() / 1000)

  return new SignJWT({
    nonce: options.nonce,
    auth_time: now
  })
    .setProtectedHeader({ alg: 'RS256', kid: keys.publicJwk.kid })
    .setIssuer(options.issuer)
    .setSubject(options.subject ?? 'test-user')
    .setAudience(options.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresIn ?? 3600))
    .sign(keys.privateKey)
}

export async function createAccessToken(
  options: CreateTokenOptions
): Promise<string> {
  const keys = await getTestKeys()
  const now = Math.floor(Date.now() / 1000)

  return new SignJWT({
    scope: 'openid'
  })
    .setProtectedHeader({ alg: 'RS256', kid: keys.publicJwk.kid })
    .setIssuer(options.issuer)
    .setSubject(options.subject ?? 'test-user')
    .setAudience(options.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresIn ?? 3600))
    .sign(keys.privateKey)
}

export async function createRefreshToken(): Promise<string> {
  // Refresh tokens are typically opaque strings
  return `refresh_${crypto.randomUUID()}`
}

export async function createTokenSet(
  options: CreateTokenOptions
): Promise<TokenSetParameters> {
  const now = Math.floor(Date.now() / 1000)

  return {
    id_token: await createIdToken(options),
    access_token: await createAccessToken(options),
    refresh_token: await createRefreshToken(),
    token_type: 'Bearer',
    expires_at: now + (options.expiresIn ?? 3600)
  }
}

export async function createExpiredTokenSet(
  options: CreateTokenOptions
): Promise<TokenSetParameters> {
  const expiredOptions = { ...options, expiresIn: -3600 }
  const now = Math.floor(Date.now() / 1000)

  return {
    id_token: await createIdToken(expiredOptions),
    access_token: await createAccessToken(expiredOptions),
    refresh_token: await createRefreshToken(),
    token_type: 'Bearer',
    expires_at: now - 3600
  }
}
