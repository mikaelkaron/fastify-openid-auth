/**
 * Type tests for fastify-openid-auth exports
 *
 * These tests verify that the public API types are correct.
 * This file is type-checked but not executed.
 */

import type { FastifyInstance, RouteHandlerMethod } from 'fastify'
import type { KeyLike } from 'jose'
import type { Client, TokenSetParameters } from 'openid-client'
import * as allExports from '../../src/index.js'
// Test index exports (re-exports everything)
import { default as defaultExport } from '../../src/index.js'
// Test login exports
import {
  type AuthorizationParametersFunction,
  openIDLoginHandlerFactory,
  SessionKeyError,
  SessionValueError,
  SupportedMethodError
} from '../../src/login.js'
// Test logout exports
import { openIDLogoutHandlerFactory } from '../../src/logout.js'
import type {
  FastifyOpenIDAuthPluginOptions,
  OpenIDAuthHandlers
} from '../../src/plugin.js'
// Test plugin exports
import { openIDAuthPlugin, default as plugin } from '../../src/plugin.js'
// Test refresh exports
import { openIDRefreshHandlerFactory } from '../../src/refresh.js'
// Test types exports
import type {
  OpenIDReadTokens,
  OpenIDTokens,
  OpenIDWriteTokens
} from '../../src/types.js'
// Test verify exports
import {
  type OpenIDVerifyOptions,
  openIDVerifyHandlerFactory
} from '../../src/verify.js'

// Type assertions

// Login handler factory should return RouteHandlerMethod
declare const client: Client
const loginHandler: RouteHandlerMethod = openIDLoginHandlerFactory(client)
const _loginHandlerWithOptions: RouteHandlerMethod = openIDLoginHandlerFactory(
  client,
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
const _sessionKeyError = new SessionKeyError()
const _sessionValueError = new SessionValueError('key')
const _supportedMethodError = new SupportedMethodError()

// Plugin exports should be functions
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
const _tokenType: OpenIDTokens = 'id_token'
const _tokenType2: OpenIDTokens = 'access_token'
const _tokenType3: OpenIDTokens = 'refresh_token'

// Read/Write tokens function types
const _readTokens: OpenIDReadTokens = async function (
  this: FastifyInstance,
  _request,
  _reply
) {
  return {} as TokenSetParameters
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
