import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { TokenSetParameters } from 'openid-client'

export type OpenIDReadTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<TokenSetParameters> | TokenSetParameters

export type OpenIDWriteTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  tokenset: TokenSetParameters
) => Promise<void> | void
