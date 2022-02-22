import { RouteHandlerMethod } from 'fastify';
import { jwtVerify, JWTVerifyGetKey, JWTVerifyOptions, KeyLike } from 'jose';
import { TokenSet } from 'openid-client';
import { OpenIDReadTokens, OpenIDWriteTokens } from './types';

export type OpenIDVerifyTokens = keyof Pick<
  TokenSet,
  'id_token' | 'access_token' | 'refresh_token'
>;

export interface OpenIDVerifyOptions {
  options?: JWTVerifyOptions;
  key: JWTVerifyGetKey | KeyLike | Uint8Array;
  tokens?: OpenIDVerifyTokens[];
  read: OpenIDReadTokens;
  write?: OpenIDWriteTokens;
}

export type OpenIDVerifyHandlerFactory = (
  options?: OpenIDVerifyOptions
) => RouteHandlerMethod;

export const openIDAuthVerifyFactory = (
  defaults: OpenIDVerifyOptions
): OpenIDVerifyHandlerFactory => {
  const openIDVerifyHandlerFactory: OpenIDVerifyHandlerFactory = (options?) => {
    const {
      options: jwtVerifyOptions,
      key,
      tokens = ['id_token'],
      read,
      write,
    } = { ...defaults, ...options };

    return async function openIDVerify(request, reply) {
      const tokenset = await read.call(this, request, reply);
      // eslint-disable-next-line @typescript-eslint/naming-convention
      for (const token of tokens) {
        const jwt = tokenset[token];
        if (jwt !== undefined) {
          key instanceof Function
            ? await jwtVerify(jwt, key, jwtVerifyOptions)
            : await jwtVerify(jwt, key, jwtVerifyOptions);
        }
      }
      return await write?.call(this, request, reply, tokenset);
    };
  };

  return openIDVerifyHandlerFactory;
};
