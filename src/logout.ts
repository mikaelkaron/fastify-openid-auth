import type { RouteHandlerMethod } from 'fastify'
import { buildEndSessionUrl, type Configuration } from 'openid-client'
import type { OpenIDReadTokens, OpenIDWriteTokens } from './types.js'
import { type OpenIDVerifyOptions, openIDJWTVerify } from './verify.js'

export type EndSessionParameters = Record<string, string>

export interface OpenIDLogoutHandlerOptions {
  parameters?: EndSessionParameters
  verify?: OpenIDVerifyOptions
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export type OpenIDLogoutHandlerFactory = (
  config: Configuration,
  options: OpenIDLogoutHandlerOptions
) => RouteHandlerMethod

export const openIDLogoutHandlerFactory: OpenIDLogoutHandlerFactory = (
  config,
  { parameters, verify, read, write }
) =>
  async function openIDLogoutHandler(request, reply) {
    const tokenset = await read.call(this, request, reply)

    if (parameters?.post_logout_redirect_uri) {
      const { pathname, search } = new URL(parameters.post_logout_redirect_uri)
      if (request.url === `${pathname}${search}`) {
        const verified = verify
          ? await openIDJWTVerify(tokenset, verify)
          : undefined
        return await write?.call(this, request, reply, tokenset, verified)
      }
    }

    const endSessionParams = { ...parameters }
    const { id_token: id_token_hint } = tokenset
    if (id_token_hint) {
      endSessionParams.id_token_hint = id_token_hint
    }
    const endSessionUrl = buildEndSessionUrl(config, endSessionParams)
    return reply.redirect(endSessionUrl.href)
  }
