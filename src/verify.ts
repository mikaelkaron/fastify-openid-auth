import { type RouteHandlerMethod } from 'fastify'
import { jwtVerify, type JWTVerifyGetKey, type JWTVerifyOptions, type KeyLike } from 'jose'
import { type TokenSetParameters } from 'openid-client'
import { type OpenIDReadTokens, type OpenIDWriteTokens } from './types'

export type OpenIDVerifyTokens = keyof Pick<
TokenSetParameters,
'id_token' | 'access_token' | 'refresh_token'
>

export interface OpenIDVerifyHandlerOptions {
  options?: JWTVerifyOptions
  key: JWTVerifyGetKey | KeyLike | Uint8Array
  tokens?: OpenIDVerifyTokens[]
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export const openIDVerifyHandlerFactory = (
  options: OpenIDVerifyHandlerOptions
): RouteHandlerMethod => {
  const {
    options: jwtVerifyOptions,
    key,
    tokens = ['id_token'],
    read,
    write
  } = options

  return async function openIDVerify (request, reply) {
    const tokenset = await read.call(this, request, reply)
    // eslint-disable-next-line @typescript-eslint/naming-convention
    for (const token of tokens) {
      const jwt = tokenset[token]
      if (jwt !== undefined) {
        key instanceof Function
          ? await jwtVerify(jwt, key, jwtVerifyOptions)
          : await jwtVerify(jwt, key, jwtVerifyOptions)
      }
    }
    return await write?.call(this, request, reply, tokenset)
  }
}
