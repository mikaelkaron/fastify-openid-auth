import { RouteHandlerMethod } from 'fastify';
import { Client, EndSessionParameters } from 'openid-client';
import { OpenIDReadTokens, OpenIDWriteTokens } from './types';

export interface OpenIDLogoutOptions {
  parameters?: EndSessionParameters;
  read: OpenIDReadTokens;
  write?: OpenIDWriteTokens;
}

export type OpenIDLogoutHandlerFactory = (
  options?: OpenIDLogoutOptions
) => RouteHandlerMethod;

export const openIDAuthLogoutFactory = (
  client: Client,
  defaults: OpenIDLogoutOptions
): OpenIDLogoutHandlerFactory => {
  const openIDLogoutHandlerFactory: OpenIDLogoutHandlerFactory = (options?) => {
    const { parameters, read, write } = { ...defaults, ...options };

    return async function openIDLogoutHandler(request, reply) {
      const tokenset = await read.call(this, request, reply);

      // #region authentication request
      if (Object.keys(request.query as object).length === 0) {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        const { id_token, session_state } = tokenset;
        if (id_token !== undefined) {
          return await reply.redirect(
            client.endSessionUrl({
              id_token_hint: id_token,
              state: session_state,
              ...parameters,
            })
          );
        }
      }
      // #endregion

      // #region authentication response
      return await write?.call(this, request, reply, tokenset);
      // #endregion
    };
  };

  return openIDLogoutHandlerFactory;
};
