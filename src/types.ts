import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { JWTVerifyResult } from 'jose'
import type { TokenEndpointResponse } from 'openid-client'

export type OpenIDTokens = 'id_token' | 'access_token' | 'refresh_token'

export type OpenIDJWTVerified = {
  [key in OpenIDTokens]?: JWTVerifyResult
}

export type OpenIDReadTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<TokenEndpointResponse> | TokenEndpointResponse

export type OpenIDWriteTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  tokenset: TokenEndpointResponse,
  verified?: OpenIDJWTVerified
) => Promise<void> | void
