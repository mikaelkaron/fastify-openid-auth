/* eslint-disable @typescript-eslint/method-signature-style */
import {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  RouteHandlerMethod,
} from 'fastify';
import fp from 'fastify-plugin';
import { jwtVerify, JWTVerifyGetKey, JWTVerifyOptions, KeyLike } from 'jose';
import {
  AuthorizationParameters,
  CallbackExtras,
  Client,
  EndSessionParameters,
  generators,
  Issuer,
  OpenIDCallbackChecks,
  RefreshExtras,
  TokenSet,
} from 'openid-client';
import { URL } from 'url';
import { format } from 'util';

declare module 'fastify' {
  interface FastifyRequest {
    session: {
      get(key: string): any;
      set(key: string, value: any): void;
    };
  }
}

type OpenIDVerifyTokens = keyof Pick<
  TokenSet,
  'id_token' | 'access_token' | 'refresh_token'
>;

export type OpenIDReadTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  client: Client
) => Promise<TokenSet> | TokenSet;

export type OpenIDWriteTokens = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  tokenset: TokenSet,
  client: Client
) => Promise<void> | void;

export interface FastifyOpenIDAuthPluginOptions {
  name: string;
  client: Client;
  login?: {
    params?: AuthorizationParameters;
    extras?: CallbackExtras;
    usePKCE?: boolean | 'plain' | 'S256';
    sessionKey?: string;
    write?: OpenIDWriteTokens;
  };
  refresh: {
    extras?: RefreshExtras;
    read: OpenIDReadTokens;
    write?: OpenIDWriteTokens;
  };
  verify: {
    options?: JWTVerifyOptions;
    key: JWTVerifyGetKey | KeyLike | Uint8Array;
    tokens?: OpenIDVerifyTokens[];
    read: OpenIDReadTokens;
    write?: OpenIDWriteTokens;
  };
  logout: {
    parameters?: EndSessionParameters;
    read: OpenIDReadTokens;
    write?: OpenIDWriteTokens;
  };
}

export type OpenIDLoginFactory = (
  options?: FastifyOpenIDAuthPluginOptions['login']
) => RouteHandlerMethod;

export type OpenIDRefreshFactory = (
  options?: FastifyOpenIDAuthPluginOptions['refresh']
) => RouteHandlerMethod;

export type OpenIDVerifyFactory = (
  options?: FastifyOpenIDAuthPluginOptions['verify']
) => RouteHandlerMethod;

export type OpenIDLogoutFactory = (
  options?: FastifyOpenIDAuthPluginOptions['logout']
) => RouteHandlerMethod;

export interface OpenIDAuthNamespace {
  login: OpenIDLoginFactory;
  refresh: OpenIDRefreshFactory;
  verify: OpenIDVerifyFactory;
  logout: OpenIDLogoutFactory;
}

const pick = <T, K extends keyof T>(obj: T, ...keys: K[]): Pick<T, K> => {
  const ret: any = {};
  keys.forEach((key) => {
    ret[key] = obj[key];
  });
  return ret;
};

const resolveResponseType = (client: Client): string | undefined => {
  const { length, 0: value } = client.metadata.response_types ?? [];

  if (length === 1) {
    return value;
  }

  return undefined;
};

const resolveRedirectUri = (client: Client): string | undefined => {
  const { length, 0: value } = client.metadata.redirect_uris ?? [];

  if (length === 1) {
    return value;
  }

  return undefined;
};

const resolveSupportedMethods = (issuer: Issuer): string => {
  const supportedMethods = Array.isArray(
    issuer.code_challenge_methods_supported
  )
    ? issuer.code_challenge_methods_supported
    : false;

  if (supportedMethods === false || supportedMethods.includes('S256')) {
    return 'S256';
  } else if (supportedMethods.includes('plain')) {
    return 'plain';
  } else {
    throw new TypeError(
      'neither code_challenge_method supported by the client is supported by the issuer'
    );
  }
};

const resolveSessionKey = (issuer: Issuer): string => {
  if (issuer.metadata.issuer === undefined) {
    throw new TypeError('client must have an issuer with an identifier');
  }
  return `oidc:${new URL(issuer.metadata.issuer).hostname}`;
};

export const openIDAuthPlugin: FastifyPluginAsync<FastifyOpenIDAuthPluginOptions> =
  fp(
    async (fastify, options) => {
      const {
        name,
        client,
        login: _login,
        refresh: _refresh,
        verify: _verify,
        logout: _logout,
      } = options;

      const _params: AuthorizationParameters = {
        scope: 'openid',
        response_type: resolveResponseType(client),
        redirect_uri: resolveRedirectUri(client),
        ..._login?.params,
      };
      const _sessionKey =
        _login?.sessionKey !== undefined
          ? _login.sessionKey
          : resolveSessionKey(client.issuer);
      const _usePKCE =
        _login?.usePKCE !== undefined
          ? _login.usePKCE === true
            ? resolveSupportedMethods(client.issuer)
            : _login.usePKCE
          : false;

      const openIDLoginFactory: OpenIDLoginFactory = (login?) => {
        const {
          sessionKey = _sessionKey,
          usePKCE = _usePKCE,
          write,
        } = { ..._login, ...login };

        return async function openIDLogin(request, reply) {
          const parameters = client.callbackParams(request.raw);

          // #region authentication request
          if (Object.keys(parameters).length === 0) {
            const params = {
              state: generators.random(),
              ..._params,
              ...login?.params,
            };
            if (params.nonce === undefined && params.response_type === 'code') {
              params.nonce = generators.random();
            }
            const sessionValue: Record<string, unknown> = pick(
              params,
              'nonce',
              'state',
              'max_age',
              'response_type'
            );
            if (usePKCE !== false && params.response_type === 'code') {
              const verifier = generators.random();

              sessionValue.code_verifier = verifier;

              switch (usePKCE) {
                case 'S256':
                  params.code_challenge = generators.codeChallenge(verifier);
                  params.code_challenge_method = 'S256';
                  break;
                case 'plain':
                  params.code_challenge = verifier;
                  break;
              }
            }

            request.session.set(sessionKey, sessionValue);

            return await reply.redirect(client.authorizationUrl(params));
          }
          // #endregion

          // #region authentication response
          const sessionValue = request.session.get(sessionKey);
          if (
            sessionValue === undefined ||
            Object.keys(sessionValue).length === 0
          ) {
            throw new Error(
              format(
                'did not find expected authorization request details in session, req.session["%s"] is %j',
                sessionKey,
                sessionValue
              )
            );
          }

          request.session.set(sessionKey, undefined);

          const params = {
            ..._params,
            ...login?.params,
          };
          const extras = { ..._login?.extras, ...login?.extras };
          // eslint-disable-next-line @typescript-eslint/naming-convention
          const { state, nonce, max_age, code_verifier, response_type } =
            sessionValue;
          const checks: OpenIDCallbackChecks = {
            state,
            nonce,
            max_age,
            code_verifier,
            response_type,
          };
          const tokenset = await client.callback(
            params.redirect_uri,
            parameters,
            checks,
            extras
          );
          return await write?.call(this, request, reply, tokenset, client);
          // #endregion
        };
      };

      const openIDRefreshFactory: OpenIDRefreshFactory = (refresh?) => {
        const { extras, read, write } = { ..._refresh, ...refresh };

        return async function openIDRefresh(request, reply) {
          const oldTokenset = await read.call(this, request, reply, client);
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
            return await write?.call(this, request, reply, newTokenset, client);
          }
        };
      };

      const openIDVerifyFactory: OpenIDVerifyFactory = (verify?) => {
        const {
          options,
          key,
          tokens = ['id_token'],
          read,
          write,
        } = { ..._verify, ...verify };

        return async function openIDVerify(request, reply) {
          const tokenset = await read.call(this, request, reply, client);
          // eslint-disable-next-line @typescript-eslint/naming-convention
          for (const token of tokens) {
            const jwt = tokenset[token];
            if (jwt !== undefined) {
              key instanceof Function
                ? await jwtVerify(jwt, key, options)
                : await jwtVerify(jwt, key, options);
            }
          }
          return await write?.call(this, request, reply, tokenset, client);
        };
      };

      const openIDLogoutFactory: OpenIDLogoutFactory = (logout?) => {
        const { parameters, read, write } = { ..._logout, ...logout };

        return async function openIDLogout(request, reply) {
          const tokenset = await read.call(this, request, reply, client);

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
          return await write?.call(this, request, reply, tokenset, client);
          // #endregion
        };
      };

      const openIDAuthNamespace: OpenIDAuthNamespace = {
        login: openIDLoginFactory,
        refresh: openIDRefreshFactory,
        verify: openIDVerifyFactory,
        logout: openIDLogoutFactory,
      };

      fastify.log.trace(
        `decorating \`fastify[${name}]\` with OpenIDAuthNamespace`
      );
      fastify.decorate(name, openIDAuthNamespace);
    },
    {
      fastify: '3.x',
      name: 'fastify-openid-auth',
      decorators: {
        request: ['session'],
      },
    }
  );

export default openIDAuthPlugin;
