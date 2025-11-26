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

    // #region authentication request
    if (Object.keys(request.query as object).length === 0) {
      const { id_token: id_token_hint } = tokenset
      const endSessionParams: Record<string, string> = {
        ...parameters
      }
      if (id_token_hint !== undefined) {
        endSessionParams.id_token_hint = id_token_hint
      }
      const endSessionUrl = buildEndSessionUrl(config, endSessionParams)
      request.log.trace('OpenID logout redirect')
      return await reply.redirect(endSessionUrl.href)
    }
    // #endregion

    // #region authentication response
    const verified =
      verify !== undefined ? await openIDJWTVerify(tokenset, verify) : undefined
    request.log.trace('OpenID logout callback')
    return await write?.call(this, request, reply, tokenset, verified)
    // #endregion
  }
