import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { TokenSet } from 'openid-client';

export type OpenIDReadTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<TokenSet> | TokenSet;

export type OpenIDWriteTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  tokenset: TokenSet
) => Promise<void> | void;
