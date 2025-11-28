import { createError } from '@fastify/error'
import type { RouteHandlerMethod } from 'fastify'
import {
  type Configuration,
  type DPoPOptions,
  refreshTokenGrant
} from 'openid-client'
import type {
  OpenIDReadTokens,
  OpenIDWriteTokens,
  Resolvable
} from './types.js'
import { resolveParameters } from './utils.js'
import { type OpenIDVerifyOptions, openIDJWTVerify } from './verify.js'

export const OpenIDRefreshTokenMissingError = createError(
  'FST_OPENID_REFRESH_TOKEN_MISSING',
  'no refresh_token available',
  400
)

export type RefreshTokenEndpointParameters = Record<string, string>

export type RefreshTokenEndpoint = {
  parameters?: Resolvable<RefreshTokenEndpointParameters>
  options?: DPoPOptions
}

export interface OpenIDRefreshHandlerOptions {
  tokenEndpoint?: RefreshTokenEndpoint
  verify?: OpenIDVerifyOptions
  read: OpenIDReadTokens
  write?: OpenIDWriteTokens
}

export type OpenIDRefreshHandlerFactory = (
  config: Configuration,
  options: OpenIDRefreshHandlerOptions
) => RouteHandlerMethod

const isTokenExpired = (expiresAt: number | undefined): boolean => {
  if (expiresAt === undefined) {
    return true
  }
  return Date.now() >= expiresAt * 1000
}

export const openIDRefreshHandlerFactory: OpenIDRefreshHandlerFactory = (
  config,
  { tokenEndpoint, verify, read, write }
) =>
  async function openIDRefreshHandler(request, reply) {
    const oldTokens = await read.call(this, request, reply)
    // expires_at comes from the index signature and may be JsonValue,
    // but we only care if it's a number
    const expiresAt =
      typeof oldTokens.expires_at === 'number'
        ? oldTokens.expires_at
        : undefined
    if (isTokenExpired(expiresAt)) {
      request.log.trace(
        expiresAt === undefined
          ? 'OpenID token missing expires_at, refreshing'
          : `OpenID token expired ${new Date(expiresAt * 1000).toUTCString()}, refreshing`
      )
      const refreshToken = oldTokens.refresh_token
      if (refreshToken === undefined) {
        throw new OpenIDRefreshTokenMissingError()
      }
      const newTokenset = await refreshTokenGrant(
        config,
        refreshToken,
        await resolveParameters(tokenEndpoint?.parameters, request, reply),
        tokenEndpoint?.options
      )
      const verified =
        verify !== undefined
          ? await openIDJWTVerify(newTokenset, verify)
          : undefined
      request.log.trace('OpenID tokens refreshed')
      return await write?.call(this, request, reply, newTokenset, verified)
    }
  }
