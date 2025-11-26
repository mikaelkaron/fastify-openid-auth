/**
 * Type tests for fastify-openid-auth exports
 *
 * These tests verify that the public API types are correct.
 * This file is type-checked but not executed.
 */

import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  RouteHandlerMethod
} from 'fastify'
import type { JWTVerifyGetKey, KeyLike } from 'jose'
import type { Client, TokenSetParameters } from 'openid-client'

// Test login exports
import {
  type AuthorizationParametersFunction,
  type OpenIDLoginHandlerFactory,
  type OpenIDLoginHandlerOptions,
  type SessionData,
  SessionKeyError,
  SessionValueError,
  SupportedMethodError,
  openIDLoginHandlerFactory
} from '../../src/login.js'

// Test logout exports
import {
  type OpenIDLogoutHandlerFactory,
  type OpenIDLogoutHandlerOptions,
  openIDLogoutHandlerFactory
} from '../../src/logout.js'

// Test refresh exports
import {
  type OpenIDRefreshHandlerFactory,
  type OpenIDRefreshHandlerOptions,
  openIDRefreshHandlerFactory
} from '../../src/refresh.js'

// Test verify exports
import {
  type OpenIDJWTVerify,
  type OpenIDVerifyHandlerFactory,
  type OpenIDVerifyHandlerOptions,
  type OpenIDVerifyOptions,
  openIDJWTVerify,
  openIDVerifyHandlerFactory
} from '../../src/verify.js'

// Test plugin exports
import { default as plugin } from '../../src/plugin.js'
import { openIDAuthPlugin } from '../../src/plugin.js'
import type {
  FastifyOpenIDAuthPluginOptions,
  OpenIDAuthHandlers
} from '../../src/plugin.js'

// Test types exports
import type {
  OpenIDJWTVerified,
  OpenIDReadTokens,
  OpenIDTokens,
  OpenIDWriteTokens
} from '../../src/types.js'

// Test index exports (re-exports everything)
import { default as defaultExport } from '../../src/index.js'
import * as allExports from '../../src/index.js'

// Type assertions

// Login handler factory should return RouteHandlerMethod
declare const client: Client
const loginHandler: RouteHandlerMethod = openIDLoginHandlerFactory(client)
const loginHandlerWithOptions: RouteHandlerMethod = openIDLoginHandlerFactory(
  client,
  {
    usePKCE: 'S256',
    sessionKey: 'test'
  }
)

// Authorization parameters function type
const authParamsFunc: AuthorizationParametersFunction = async (
  request,
  reply
) => ({
  scope: 'openid profile'
})

// Verify options type
const verifyOptions: OpenIDVerifyOptions = {
  key: {} as KeyLike,
  tokens: ['id_token', 'access_token'],
  options: { issuer: 'test' }
}

// Verify handler factory should return RouteHandlerMethod
const verifyHandler: RouteHandlerMethod = openIDVerifyHandlerFactory({
  ...verifyOptions,
  read: async () => ({}) as TokenSetParameters
})

// Refresh handler factory should return RouteHandlerMethod
const refreshHandler: RouteHandlerMethod = openIDRefreshHandlerFactory(client, {
  read: async () => ({}) as TokenSetParameters
})

// Logout handler factory should return RouteHandlerMethod
const logoutHandler: RouteHandlerMethod = openIDLogoutHandlerFactory(client, {
  read: async () => ({}) as TokenSetParameters
})

// Error classes should be constructable
const sessionKeyError = new SessionKeyError()
const sessionValueError = new SessionValueError('key')
const supportedMethodError = new SupportedMethodError()

// Plugin exports should be functions
if (typeof plugin !== 'function') throw new Error('plugin should be a function')
if (typeof openIDAuthPlugin !== 'function')
  throw new Error('openIDAuthPlugin should be a function')

// OpenIDAuthHandlers type check
const handlers: OpenIDAuthHandlers = {
  login: loginHandler,
  verify: verifyHandler,
  refresh: refreshHandler,
  logout: logoutHandler
}

// Plugin options type check
const pluginOptions: FastifyOpenIDAuthPluginOptions = {
  decorator: 'openid',
  client,
  verify: {
    ...verifyOptions,
    read: async () => ({}) as TokenSetParameters
  },
  refresh: {
    read: async () => ({}) as TokenSetParameters
  },
  logout: {
    read: async () => ({}) as TokenSetParameters
  }
}

// OpenIDTokens should be a union of token keys
const tokenType: OpenIDTokens = 'id_token'
const tokenType2: OpenIDTokens = 'access_token'
const tokenType3: OpenIDTokens = 'refresh_token'

// Read/Write tokens function types
const readTokens: OpenIDReadTokens = async function (
  this: FastifyInstance,
  request,
  reply
) {
  return {} as TokenSetParameters
}

const writeTokens: OpenIDWriteTokens = async function (
  this: FastifyInstance,
  request,
  reply,
  tokenset,
  verified
) {
  // void return
}

// Default export should be the plugin
const pluginExport: typeof plugin = defaultExport

// Runtime check that all exports exist
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
