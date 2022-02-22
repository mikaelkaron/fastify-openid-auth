import { RouteHandlerMethod } from 'fastify';
import { Client, RefreshExtras } from 'openid-client';
import { OpenIDReadTokens, OpenIDWriteTokens } from './types';

export interface OpenIDRefreshOptions {
  extras?: RefreshExtras;
  read: OpenIDReadTokens;
  write?: OpenIDWriteTokens;
}

export type OpenIDRefreshHandlerFactory = (
  options?: OpenIDRefreshOptions
) => RouteHandlerMethod;

export const openIDAuthRefreshFactory = (
  client: Client,
  defaults: OpenIDRefreshOptions
): OpenIDRefreshHandlerFactory => {
  const openIDRefreshHandlerFactory: OpenIDRefreshHandlerFactory = (
    options?
  ) => {
    const { extras, read, write } = { ...defaults, ...options };

    return async function openIDRefreshHandler(request, reply) {
      const oldTokenset = await read.call(this, request, reply);
      if (oldTokenset.expired()) {
        request.log.trace(
          `OpenID token expired ${
            oldTokenset.expires_at !== undefined
              ? new Date(oldTokenset.expires_at * 1000).toUTCString()
              : 'recently'
          }, refreshing`
        );
        const newTokenset = await client.refresh(oldTokenset, extras);
        request.log.trace('OpenID tokens refreshed');
        return await write?.call(this, request, reply, newTokenset);
      }
    };
  };

  return openIDRefreshHandlerFactory;
};
