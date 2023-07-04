import { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { type JWTVerifyResult } from 'jose'
import { type TokenSetParameters } from 'openid-client'

export type OpenIDTokens = keyof Pick<
TokenSetParameters,
'id_token' | 'access_token' | 'refresh_token'
>

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
  verified?: Map<OpenIDTokens, JWTVerifyResult>
) => Promise<void> | void
