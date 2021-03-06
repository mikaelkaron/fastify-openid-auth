import { FastifyPluginAsync, RouteHandlerMethod } from 'fastify';
import fp from 'fastify-plugin';
import { Client } from 'openid-client';
import { openIDLoginHandlerFactory, OpenIDLoginHandlerOptions } from './login';
import {
  openIDLogoutHandlerFactory,
  OpenIDLogoutHandlerOptions,
} from './logout';
import {
  openIDRefreshHandlerFactory,
  OpenIDRefreshHandlerOptions,
} from './refresh';
import {
  openIDVerifyHandlerFactory,
  OpenIDVerifyHandlerOptions,
} from './verify';

export interface FastifyOpenIDAuthPluginOptions {
  name: string;
  client: Client;
  login?: OpenIDLoginHandlerOptions;
  verify: OpenIDVerifyHandlerOptions;
  refresh: OpenIDRefreshHandlerOptions;
  logout: OpenIDLogoutHandlerOptions;
}

export interface OpenIDAuthNamespace {
  login: RouteHandlerMethod;
  verify: RouteHandlerMethod;
  refresh: RouteHandlerMethod;
  logout: RouteHandlerMethod;
}

export const openIDAuthPlugin: FastifyPluginAsync<FastifyOpenIDAuthPluginOptions> =
  fp(
    async (fastify, options) => {
      const { name, client, login, refresh, verify, logout } = options;

      const openIDAuthNamespace: OpenIDAuthNamespace = {
        login: openIDLoginHandlerFactory(client, login),
        refresh: openIDRefreshHandlerFactory(client, refresh),
        verify: openIDVerifyHandlerFactory(verify),
        logout: openIDLogoutHandlerFactory(client, logout),
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
