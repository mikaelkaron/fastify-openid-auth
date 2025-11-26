import type {
  FastifyPluginAsync,
  FastifyPluginOptions,
  RouteHandlerMethod
} from 'fastify'
import fp from 'fastify-plugin'
import type { Configuration } from 'openid-client'
import {
  type OpenIDLoginHandlerOptions,
  openIDLoginHandlerFactory
} from './login.js'
import {
  type OpenIDLogoutHandlerOptions,
  openIDLogoutHandlerFactory
} from './logout.js'
import {
  type OpenIDRefreshHandlerOptions,
  openIDRefreshHandlerFactory
} from './refresh.js'
import {
  type OpenIDVerifyHandlerOptions,
  openIDVerifyHandlerFactory
} from './verify.js'

export type FastifyOpenIDAuthPluginOptions = FastifyPluginOptions & {
  decorator: string | symbol
  config: Configuration
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

export const openIDAuthPlugin: FastifyPluginAsync<
  FastifyOpenIDAuthPluginOptions
> = async (fastify, options) => {
  const { decorator, config, login, refresh, verify, logout } = options

  const openIDAuthHandlers: OpenIDAuthHandlers = {
    login: openIDLoginHandlerFactory(config, login),
    refresh: openIDRefreshHandlerFactory(config, refresh),
    verify: openIDVerifyHandlerFactory(verify),
    logout: openIDLogoutHandlerFactory(config, logout)
  }

  fastify.log.trace(
    `decorating \`fastify[${String(decorator)}]\` with OpenIDAuthHandlers`
  )
  fastify.decorate(decorator, openIDAuthHandlers)
}

export default fp(openIDAuthPlugin, {
  fastify: '5.x',
  name: 'fastify-openid-auth',
  decorators: {
    request: ['session']
  }
})
