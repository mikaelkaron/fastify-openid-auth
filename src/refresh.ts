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
  if (oldTokenset.expires_at === undefined || oldTokenset.expired()) {
    request.log.trace(oldTokenset.expires_at === undefined
      ? 'OpenID token missing expires_at, refreshing'
      : `OpenID token expired ${new Date(oldTokenset.expires_at * 1000).toUTCString()}, refreshing`
    )
    const newTokenset = await client.refresh(oldTokenset, extras)
    const verified = verify !== undefined
      ? await openIDJWTVerify(newTokenset, verify)
      : undefined
    request.log.trace('OpenID tokens refreshed')
    return await write?.call(this, request, reply, newTokenset, verified)
  }
}
