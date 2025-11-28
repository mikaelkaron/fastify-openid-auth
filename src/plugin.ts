import type { FastifyPluginAsync, RouteHandlerMethod } from 'fastify'
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

export interface OpenIDAuthHandlers {
  login: RouteHandlerMethod
  verify: RouteHandlerMethod
  refresh: RouteHandlerMethod
  logout: RouteHandlerMethod
}

export type OpenIDHandlersOptions = {
  login?: OpenIDLoginHandlerOptions
  verify: OpenIDVerifyHandlerOptions
  refresh: OpenIDRefreshHandlerOptions
  logout: OpenIDLogoutHandlerOptions
}

export type OpenIDHandlersFactory = (
  config: Configuration,
  options: OpenIDHandlersOptions
) => OpenIDAuthHandlers

export const openIDHandlersFactory: OpenIDHandlersFactory = (
  config,
  { login, refresh, verify, logout }
) => ({
  login: openIDLoginHandlerFactory(config, login),
  refresh: openIDRefreshHandlerFactory(config, refresh),
  verify: openIDVerifyHandlerFactory(verify),
  logout: openIDLogoutHandlerFactory(config, logout)
})

export type FastifyOpenIDAuthPluginOptions = OpenIDHandlersOptions & {
  decorator: string | symbol
  config: Configuration
}

export const openIDAuthPlugin: FastifyPluginAsync<
  FastifyOpenIDAuthPluginOptions
> = async (fastify, options) => {
  const { decorator, config, ...rest } = options
  fastify.log.trace(
    `decorating \`fastify[${String(decorator)}]\` with OpenIDAuthHandlers`
  )
  fastify.decorate(decorator, openIDHandlersFactory(config, rest))
}

export default fp(openIDAuthPlugin, {
  fastify: '5.x',
  name: 'fastify-openid-auth',
  decorators: {
    request: ['session']
  }
})
