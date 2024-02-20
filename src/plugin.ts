import { type FastifyPluginAsync, type FastifyPluginOptions, type RouteHandlerMethod } from 'fastify'
import fp from 'fastify-plugin'
import { type Client } from 'openid-client'
import { openIDLoginHandlerFactory, type OpenIDLoginHandlerOptions } from './login.js'
import {
  openIDLogoutHandlerFactory,
  type OpenIDLogoutHandlerOptions
} from './logout.js'
import {
  openIDRefreshHandlerFactory,
  type OpenIDRefreshHandlerOptions
} from './refresh.js'
import {
  openIDVerifyHandlerFactory,
  type OpenIDVerifyHandlerOptions
} from './verify.js'

export type FastifyOpenIDAuthPluginOptions = FastifyPluginOptions & {
  decorator: string | symbol
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
  async (fastify, options) => {
    const { decorator, client, login, refresh, verify, logout } = options

    const openIDAuthHandlers: OpenIDAuthHandlers = {
      login: openIDLoginHandlerFactory(client, login),
      refresh: openIDRefreshHandlerFactory(client, refresh),
      verify: openIDVerifyHandlerFactory(verify),
      logout: openIDLogoutHandlerFactory(client, logout)
    }

    fastify.log.trace(
      `decorating \`fastify[${String(decorator)}]\` with OpenIDAuthHandlers`
    )
    fastify.decorate(decorator, openIDAuthHandlers)
  }

export default fp(openIDAuthPlugin, {
  fastify: '4.x',
  name: 'fastify-openid-auth',
  decorators: {
    request: ['session']
  }
})
