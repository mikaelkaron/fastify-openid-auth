import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { JWTVerifyResult } from 'jose'
import type { TokenEndpointResponse } from 'openid-client'

export type ParametersFunction<T> = (
  request: FastifyRequest,
  reply: FastifyReply
) => T | PromiseLike<T>

export type ParametersOrParameterFunction<T> = T | ParametersFunction<T>

export type OpenIDTokens = 'id_token' | 'access_token' | 'refresh_token'

export type OpenIDJWTVerified = {
  [key in OpenIDTokens]?: JWTVerifyResult
}

export type OpenIDReadTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
) =>
  | PromiseLike<Partial<TokenEndpointResponse>>
  | Partial<TokenEndpointResponse>

export type OpenIDWriteTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  tokenset?: Partial<TokenEndpointResponse>,
  verified?: OpenIDJWTVerified
) => PromiseLike<void> | void
