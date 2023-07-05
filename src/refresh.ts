import { type RouteHandlerMethod } from 'fastify'
import { TokenSet, type Client, type RefreshExtras } from 'openid-client'
import { type OpenIDReadTokens, type OpenIDWriteTokens } from './types.js'
import { openIDJWTVerify, type OpenIDVerifyOptions } from './verify.js'

export interface OpenIDRefreshHandlerOptions {
  extras?: RefreshExtras
  verify?: OpenIDVerifyOptions
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export type OpenIDRefreshHandlerFactory = (
  client: Client,
  options: OpenIDRefreshHandlerOptions
) => RouteHandlerMethod

export const openIDRefreshHandlerFactory: OpenIDRefreshHandlerFactory = (
  client,
  {
    extras,
    verify,
    read,
    write
  }
) => async function openIDRefreshHandler (request, reply) {
  const oldTokenset = new TokenSet(await read.call(this, request, reply))
  if (oldTokenset.expired()) {
    request.log.trace(
      `OpenID token expired ${oldTokenset.expires_at !== undefined
        ? new Date(oldTokenset.expires_at * 1000).toUTCString()
        : 'recently'
      }, refreshing`
    )
    const newTokenset = await client.refresh(oldTokenset, extras)
    const verified = verify !== undefined
      ? await openIDJWTVerify(newTokenset, verify)
      : undefined
    request.log.trace('OpenID tokens refreshed')
    return await write?.call(this, request, reply, newTokenset, verified)
  }
}
