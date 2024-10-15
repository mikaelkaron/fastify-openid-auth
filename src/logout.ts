import type { RouteHandlerMethod } from 'fastify'
import type { Client, EndSessionParameters } from 'openid-client'
import type { OpenIDReadTokens, OpenIDWriteTokens } from './types.js'
import { type OpenIDVerifyOptions, openIDJWTVerify } from './verify.js'

export interface OpenIDLogoutHandlerOptions {
  parameters?: EndSessionParameters
  verify?: OpenIDVerifyOptions
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export type OpenIDLogoutHandlerFactory = (
  client: Client,
  options: OpenIDLogoutHandlerOptions
) => RouteHandlerMethod

export const openIDLogoutHandlerFactory: OpenIDLogoutHandlerFactory = (
  client,
  { parameters, verify, read, write }
) =>
  async function openIDLogoutHandler(request, reply) {
    const tokenset = await read.call(this, request, reply)

    // #region authentication request
    if (Object.keys(request.query as object).length === 0) {
      // eslint-disable-next-line @typescript-eslint/naming-convention
      const { id_token: id_token_hint, session_state: state } = tokenset
      request.log.trace('OpenID logout redirect')
      return await reply.redirect(
        client.endSessionUrl({
          id_token_hint,
          state,
          ...parameters
        })
      )
    }
    // #endregion

    // #region authentication response
    const verified =
      verify !== undefined ? await openIDJWTVerify(tokenset, verify) : undefined
    request.log.trace('OpenID logout callback')
    return await write?.call(this, request, reply, tokenset, verified)
    // #endregion
  }
