/**
 * Type tests for fastify-openid-auth exports
 *
 * These tests verify that the public API types are correct.
 * This file is type-checked but not executed.
 */

// Imports: grouped by feature
import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  RouteHandlerMethod
} from 'fastify'
import type { CryptoKey } from 'jose'
import type { Configuration, TokenEndpointResponse } from 'openid-client'
import * as allExports from '../../src/index.js'
import { default as defaultExport } from '../../src/index.js'
// Login
import {
  type AuthorizationParametersFunction,
  openIDLoginHandlerFactory,
  SessionKeyError,
  SessionValueError,
  SupportedMethodError
} from '../../src/login.js'
// Logout
import { openIDLogoutHandlerFactory } from '../../src/logout.js'
import type {
  FastifyOpenIDAuthPluginOptions,
  OpenIDAuthHandlers
} from '../../src/plugin.js'
// Plugin
import {
  openIDAuthPlugin,
  openIDHandlersFactory,
  default as plugin
} from '../../src/plugin.js'
// Refresh
import { openIDRefreshHandlerFactory } from '../../src/refresh.js'
// Types
import type {
  OpenIDReadTokens,
  OpenIDTokens,
  OpenIDWriteTokens
} from '../../src/types.js'
// Verify
import {
  type OpenIDVerifyOptions,
  openIDVerifyHandlerFactory
} from '../../src/verify.js'

// --- Type assertions ---
// Login handler factory
const mockConfig = {} as Configuration
const loginHandler: RouteHandlerMethod = openIDLoginHandlerFactory(mockConfig)
const _loginHandlerWithOptions: RouteHandlerMethod = openIDLoginHandlerFactory(
  mockConfig,
  {
    usePKCE: 'S256',
    sessionKey: 'test'
  }
)
// Authorization parameters function type
const _authParamsFunc: AuthorizationParametersFunction = async (
  _request,
  _reply
) => ({
  scope: 'openid profile'
})

// Logout handler factory
const logoutHandler: RouteHandlerMethod = openIDLogoutHandlerFactory(
  mockConfig,
  {
    read: async () => ({}) as TokenEndpointResponse
  }
)

// Refresh handler factory
const refreshHandler: RouteHandlerMethod = openIDRefreshHandlerFactory(
  mockConfig,
  {
    read: async () => ({}) as TokenEndpointResponse
  }
)
// Dynamic parameters function for refresh
const _refreshParamsFunc: (
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<{ scope: string; custom: string }> = async (_request, _reply) => ({
  scope: 'openid',
  custom: 'value'
})
const _refreshHandlerWithParams: RouteHandlerMethod =
  openIDRefreshHandlerFactory(mockConfig, {
    parameters: _refreshParamsFunc,
    read: async () => ({}) as TokenEndpointResponse
  })

// Verify handler factory
const verifyOptions: OpenIDVerifyOptions = {
  key: {} as CryptoKey,
  tokens: ['id_token', 'access_token'],
  options: { issuer: 'test' }
}
const verifyHandler: RouteHandlerMethod = openIDVerifyHandlerFactory({
  ...verifyOptions,
  read: async () => ({}) as TokenEndpointResponse
})

// Error classes
const _sessionKeyError = new SessionKeyError()
const _sessionValueError = new SessionValueError('key')
const _supportedMethodError = new SupportedMethodError()

// Plugin exports
if (typeof plugin !== 'function') throw new Error('plugin should be a function')
if (typeof openIDAuthPlugin !== 'function')
  throw new Error('openIDAuthPlugin should be a function')

// OpenIDAuthHandlers type check
const _handlers: OpenIDAuthHandlers = {
  login: loginHandler,
  verify: verifyHandler,
  refresh: refreshHandler,
  logout: logoutHandler
}
// Plugin options type check
const _pluginOptions: FastifyOpenIDAuthPluginOptions = {
  decorator: 'openid',
  config: mockConfig,
  verify: {
    ...verifyOptions,
    read: async () => ({}) as TokenEndpointResponse
  },
  refresh: {
    read: async () => ({}) as TokenEndpointResponse
  },
  logout: {
    read: async () => ({}) as TokenEndpointResponse
  }
}

// Handlers from decorator
const fastifyInstance = {} as FastifyInstance & { openid: OpenIDAuthHandlers }
const { login, verify, refresh, logout } = fastifyInstance.openid
const _loginHandler: RouteHandlerMethod = login
const _verifyHandler: RouteHandlerMethod = verify
const _refreshHandler: RouteHandlerMethod = refresh
const _logoutHandler: RouteHandlerMethod = logout

// Fastify route config using verify as preHandler
interface AuthRequest extends FastifyInstance {
  'auth-tokens'?: TokenEndpointResponse
}
const _routeConfig = {
  preHandler: verify,
  handler: async (request: AuthRequest) => {
    return { user: request['auth-tokens'] }
  }
}

// OpenIDTokens union
const _tokenType: OpenIDTokens = 'id_token'
const _tokenType2: OpenIDTokens = 'access_token'
const _tokenType3: OpenIDTokens = 'refresh_token'

// Read/Write tokens function types
const _readTokens: OpenIDReadTokens = async function (
  this: FastifyInstance,
  _request,
  _reply
) {
  return {} as TokenEndpointResponse
}
const _writeTokens: OpenIDWriteTokens = async function (
  this: FastifyInstance,
  _request,
  _reply,
  _tokenset,
  _verified
) {
  // void return
}

// Default export should be the plugin
const _pluginExport: typeof plugin = defaultExport

// openIDHandlersFactory type assertion
const _handlersFactoryResult = openIDHandlersFactory(mockConfig, {
  login: { parameters: { scope: 'openid' } },
  verify: { ...verifyOptions, read: async () => ({}) as TokenEndpointResponse },
  refresh: { read: async () => ({}) as TokenEndpointResponse },
  logout: { read: async () => ({}) as TokenEndpointResponse }
})
const _handlersFactoryTypeCheck: OpenIDAuthHandlers = _handlersFactoryResult

// --- Runtime existence checks ---
if (!allExports.openIDHandlersFactory)
  throw new Error('Missing openIDHandlersFactory')
if (!allExports.openIDLoginHandlerFactory)
  throw new Error('Missing openIDLoginHandlerFactory')
if (!allExports.openIDVerifyHandlerFactory)
  throw new Error('Missing openIDVerifyHandlerFactory')
if (!allExports.openIDRefreshHandlerFactory)
  throw new Error('Missing openIDRefreshHandlerFactory')
if (!allExports.openIDLogoutHandlerFactory)
  throw new Error('Missing openIDLogoutHandlerFactory')
if (!allExports.openIDAuthPlugin) throw new Error('Missing openIDAuthPlugin')

console.log('Type tests passed')
