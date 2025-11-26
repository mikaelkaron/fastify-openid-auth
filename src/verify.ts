import type { RouteHandlerMethod } from 'fastify'
import {
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
  jwtVerify,
  type KeyLike
} from 'jose'
import type { TokenSetParameters } from 'openid-client'
import type {
  OpenIDJWTVerified,
  OpenIDReadTokens,
  OpenIDTokens,
  OpenIDWriteTokens
} from './types.js'

export interface OpenIDVerifyOptions {
  options?: JWTVerifyOptions
  key: JWTVerifyGetKey | KeyLike | Uint8Array
  tokens: OpenIDTokens[]
}

export type OpenIDJWTVerify = (
  tokenset: TokenSetParameters,
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
      const result =
        key instanceof Function
          ? await jwtVerify(jwt, key, options)
          : await jwtVerify(jwt, key, options)
      verified[token] = result
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
    const verified = await openIDJWTVerify(tokenset, verify)
    request.log.trace('OpenID tokens verified')
    return await write?.call(this, request, reply, tokenset, verified)
  }
