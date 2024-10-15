import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { JWTVerifyResult } from 'jose'
import type { TokenSetParameters } from 'openid-client'

export type OpenIDTokens = keyof Pick<
  TokenSetParameters,
  'id_token' | 'access_token' | 'refresh_token'
>

export type OpenIDJWTVerified = {
  [key in OpenIDTokens]?: JWTVerifyResult
}

export type OpenIDReadTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<TokenSetParameters> | TokenSetParameters

export type OpenIDWriteTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  tokenset: TokenSetParameters,
  verified?: OpenIDJWTVerified
) => Promise<void> | void
