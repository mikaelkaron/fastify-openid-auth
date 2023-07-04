import { type RouteHandlerMethod } from 'fastify'
import { type Client, type RefreshExtras, TokenSet } from 'openid-client'
import { type OpenIDReadTokens, type OpenIDWriteTokens } from './types'

export interface OpenIDRefreshHandlerOptions {
  extras?: RefreshExtras
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export const openIDRefreshHandlerFactory = (
  client: Client,
  options: OpenIDRefreshHandlerOptions
): RouteHandlerMethod => {
  const { extras, read, write } = options

  return async function openIDRefreshHandler (request, reply) {
    const oldTokenset = new TokenSet(await read.call(this, request, reply))
    if (oldTokenset.expired()) {
      request.log.trace(
        `OpenID token expired ${
          oldTokenset.expires_at !== undefined
            ? new Date(oldTokenset.expires_at * 1000).toUTCString()
            : 'recently'
        }, refreshing`
      )
      const newTokenset = await client.refresh(oldTokenset, extras)
      request.log.trace('OpenID tokens refreshed')
      return await write?.call(this, request, reply, newTokenset)
    }
  }
}
