import { type FastifyPluginAsync, type RouteHandlerMethod } from 'fastify'
import fp from 'fastify-plugin'
import { type Client } from 'openid-client'
import { openIDLoginHandlerFactory, type OpenIDLoginHandlerOptions } from './login'
import {
  openIDLogoutHandlerFactory,
  type OpenIDLogoutHandlerOptions
} from './logout'
import {
  openIDRefreshHandlerFactory,
  type OpenIDRefreshHandlerOptions
} from './refresh'
import {
  openIDVerifyHandlerFactory,
  type OpenIDVerifyHandlerOptions
} from './verify'

export interface FastifyOpenIDAuthPluginOptions {
  name: string
  client: Client
  login?: OpenIDLoginHandlerOptions
  verify: OpenIDVerifyHandlerOptions
  refresh: OpenIDRefreshHandlerOptions
  logout: OpenIDLogoutHandlerOptions
}

export interface OpenIDAuthHandlers {
  login: RouteHandlerMethod
  verify: RouteHandlerMethod
  refresh: RouteHandlerMethod
  logout: RouteHandlerMethod
}

export const openIDAuthPlugin: FastifyPluginAsync<FastifyOpenIDAuthPluginOptions> =
  fp(
    async (fastify, options) => {
      const { name, client, login, refresh, verify, logout } = options

      const openIDAuthHandlers: OpenIDAuthHandlers = {
        login: openIDLoginHandlerFactory(client, login),
        refresh: openIDRefreshHandlerFactory(client, refresh),
        verify: openIDVerifyHandlerFactory(verify),
        logout: openIDLogoutHandlerFactory(client, logout)
      }

      fastify.log.trace(
        `decorating \`fastify[${name}]\` with OpenIDAuthNamespace`
      )
      fastify.decorate(name, openIDAuthNamespace)
    },
    {
      fastify: '4.x',
      name: 'fastify-openid-auth',
      decorators: {
        request: ['session']
      }
    }
  )
