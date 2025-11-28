import type { RouteHandlerMethod } from 'fastify'
import {
  type CryptoKey,
  type JWK,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
  jwtVerify,
  type KeyObject
} from 'jose'
import type { TokenEndpointResponse } from 'openid-client'
import type {
  OpenIDJWTVerified,
  OpenIDReadTokens,
  OpenIDTokens,
  OpenIDWriteTokens
} from './types.js'

export interface OpenIDVerifyOptions {
  options?: JWTVerifyOptions
  key: JWTVerifyGetKey | CryptoKey | KeyObject | JWK | Uint8Array
  tokens: OpenIDTokens[]
}

export type OpenIDJWTVerify = (
  tokenset: Partial<Pick<TokenEndpointResponse, OpenIDTokens>>,
  options: OpenIDVerifyOptions
) => Promise<OpenIDJWTVerified>

export const openIDJWTVerify: OpenIDJWTVerify = async (
  tokenset,
  { key, options, tokens }
) => {
  const verified: OpenIDJWTVerified = {}
  for (const token of tokens) {
    const jwt = tokenset[token]
    if (jwt !== undefined) {
      // TypeScript requires separate calls for function vs static key overloads
      verified[token] =
        typeof key === 'function'
          ? await jwtVerify(jwt, key, options)
          : await jwtVerify(jwt, key, options)
    }
  }
  return verified
}

export interface OpenIDVerifyHandlerOptions extends OpenIDVerifyOptions {
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export type OpenIDVerifyHandlerFactory = ({
  options,
  key,
  tokens,
  read,
  write
}: OpenIDVerifyHandlerOptions) => RouteHandlerMethod

export const openIDVerifyHandlerFactory: OpenIDVerifyHandlerFactory = ({
  read,
  write,
  ...verify
}) =>
  async function openIDVerifyHandler(request, reply) {
    const tokenset = await read.call(this, request, reply)
    const verified = tokenset
      ? await openIDJWTVerify(tokenset, verify)
      : undefined
    request.log.trace('OpenID tokens verified')
    return await write?.call(this, request, reply, tokenset, verified)
  }
