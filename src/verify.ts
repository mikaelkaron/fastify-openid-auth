import { type RouteHandlerMethod } from 'fastify'
import { jwtVerify, type JWTVerifyGetKey, type JWTVerifyOptions, type JWTVerifyResult, type KeyLike } from 'jose'
import { type TokenSetParameters } from 'openid-client'
import { type OpenIDReadTokens, type OpenIDTokens, type OpenIDWriteTokens } from './types'

export interface OpenIDVerifyOptions {
  options?: JWTVerifyOptions
  key: JWTVerifyGetKey | KeyLike | Uint8Array
  tokens: OpenIDTokens[]
}

export type OpenIDJWTVerify = (tokenset: TokenSetParameters, options: OpenIDVerifyOptions) => Promise<Map<OpenIDTokens, JWTVerifyResult>>

export const openIDJWTVerify: OpenIDJWTVerify = async (tokenset, { key, options, tokens }) => {
  const verified = new Map<OpenIDTokens, JWTVerifyResult>()
  for (const token of tokens) {
    const jwt = tokenset[token]
    if (jwt !== undefined) {
      const result = key instanceof Function
        ? await jwtVerify(jwt, key, options)
        : await jwtVerify(jwt, key, options)
      verified.set(token, result)
    }
  }
  return verified
}

export interface OpenIDVerifyHandlerOptions extends OpenIDVerifyOptions {
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export type OpenIDVerifyHandlerFactory = (
  {
    options,
    key,
    tokens,
    read,
    write
  }: OpenIDVerifyHandlerOptions
) => RouteHandlerMethod

export const openIDVerifyHandlerFactory: OpenIDVerifyHandlerFactory = (
  {
    read,
    write,
    ...verify
  }
) => async function openIDVerifyHandler (request, reply) {
  const tokenset = await read.call(this, request, reply)
  const verified = await openIDJWTVerify(tokenset, verify)
  return await write?.call(this, request, reply, tokenset, verified)
}
