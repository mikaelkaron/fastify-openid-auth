/* eslint-disable @typescript-eslint/method-signature-style */
import { RouteHandlerMethod } from 'fastify';
import {
  AuthorizationParameters,
  CallbackExtras,
  Client,
  generators,
  Issuer,
  OpenIDCallbackChecks,
} from 'openid-client';
import { format } from 'util';
import { OpenIDWriteTokens } from './types';

declare module 'fastify' {
  interface FastifyRequest {
    session: {
      get(key: string): any;
      set(key: string, value: any): void;
    };
  }
}

export interface OpenIDLoginOptions {
  params?: AuthorizationParameters;
  extras?: CallbackExtras;
  usePKCE?: boolean | 'plain' | 'S256';
  sessionKey?: string;
  write?: OpenIDWriteTokens;
}

export type OpenIDLoginHandlerFactory = (
  options?: OpenIDLoginOptions
) => RouteHandlerMethod;

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

export const openIDAuthLoginFactory = (
  client: Client,
  defaults?: OpenIDLoginOptions
): OpenIDLoginHandlerFactory => {
  const _params: AuthorizationParameters = {
    scope: 'openid',
    response_type: resolveResponseType(client),
    redirect_uri: resolveRedirectUri(client),
    ...defaults?.params,
  };
  const _sessionKey =
    defaults?.sessionKey !== undefined
      ? defaults.sessionKey
      : resolveSessionKey(client.issuer);
  const _usePKCE =
    defaults?.usePKCE !== undefined
      ? defaults.usePKCE === true
        ? resolveSupportedMethods(client.issuer)
        : defaults.usePKCE
      : false;

  const openIDLoginHandlerFactory: OpenIDLoginHandlerFactory = (options?) => {
    const {
      sessionKey = _sessionKey,
      usePKCE = _usePKCE,
      write,
    } = { ...defaults, ...options };

    return async function openIDLoginHandler(request, reply) {
      const parameters = client.callbackParams(request.raw);

      // #region authentication request
      if (Object.keys(parameters).length === 0) {
        const params = {
          state: generators.random(),
          ..._params,
          ...options?.params,
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
        ...options?.params,
      };
      const extras = { ...defaults?.extras, ...options?.extras };
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
      return await write?.call(this, request, reply, tokenset);
      // #endregion
    };
  };

  return openIDLoginHandlerFactory;
};
