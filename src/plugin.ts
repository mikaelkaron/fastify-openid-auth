import { FastifyPluginAsync } from 'fastify';
import fp from 'fastify-plugin';
import { Client } from 'openid-client';
import {
  openIDAuthLoginFactory,
  OpenIDLoginHandlerFactory,
  OpenIDLoginOptions,
} from './login';
import {
  openIDAuthLogoutFactory,
  OpenIDLogoutHandlerFactory,
  OpenIDLogoutOptions,
} from './logout';
import {
  openIDAuthRefreshFactory,
  OpenIDRefreshHandlerFactory,
  OpenIDRefreshOptions,
} from './refresh';
import {
  openIDAuthVerifyFactory,
  OpenIDVerifyHandlerFactory,
  OpenIDVerifyOptions,
} from './verify';

export interface FastifyOpenIDAuthPluginOptions {
  name: string;
  client: Client;
  login?: OpenIDLoginOptions;
  verify: OpenIDVerifyOptions;
  refresh: OpenIDRefreshOptions;
  logout: OpenIDLogoutOptions;
}

export interface OpenIDAuthNamespace {
  login: OpenIDLoginHandlerFactory;
  verify: OpenIDVerifyHandlerFactory;
  refresh: OpenIDRefreshHandlerFactory;
  logout: OpenIDLogoutHandlerFactory;
}

export const openIDAuthPlugin: FastifyPluginAsync<FastifyOpenIDAuthPluginOptions> =
  fp(
    async (fastify, options) => {
      const { name, client, login, refresh, verify, logout } = options;

      const openIDAuthNamespace: OpenIDAuthNamespace = {
        login: openIDAuthLoginFactory(client, login),
        refresh: openIDAuthRefreshFactory(client, refresh),
        verify: openIDAuthVerifyFactory(verify),
        logout: openIDAuthLogoutFactory(client, logout),
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
