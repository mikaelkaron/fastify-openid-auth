import createError from '@fastify/error'
import type { RouteHandlerMethod } from 'fastify'
import {
  type AuthorizationCodeGrantOptions,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  type Configuration,
  calculatePKCECodeChallenge,
  randomNonce,
  randomPKCECodeVerifier,
  randomState
} from 'openid-client'
import type { OpenIDWriteTokens, Resolvable } from './types.js'
import { type OpenIDVerifyOptions, openIDJWTVerify } from './verify.js'

declare module 'fastify' {
  interface FastifyRequest {
    session: Session
  }

  type Session<T = SessionData> = Partial<T> & {
    get<Key extends keyof T>(key: Key): T[Key] | undefined
    set<Key extends keyof T>(key: Key, value: T[Key] | undefined): void
  }
}

// biome-ignore lint/suspicious/noExplicitAny: User can supply `any` type in the app
export type SessionData = Record<string, any>

export type AuthorizationParameters = Record<string, string>

export type AuthorizationTokenEndpointParameters = Record<string, string>

export type AuthorizationTokenEndpoint = {
  parameters?: Resolvable<AuthorizationTokenEndpointParameters>
  options?: AuthorizationCodeGrantOptions
}

export interface CallbackChecks {
  state?: string
  nonce?: string
  pkceCodeVerifier?: string
}

export interface OpenIDLoginHandlerOptions {
  parameters?: Resolvable<AuthorizationParameters>
  usePKCE?: boolean | 'plain' | 'S256'
  sessionKey?: string
  tokenEndpoint?: AuthorizationTokenEndpoint
  verify?: OpenIDVerifyOptions
  write?: OpenIDWriteTokens
}

export type OpenIDLoginHandlerFactory = (
  config: Configuration,
  options?: OpenIDLoginHandlerOptions
) => RouteHandlerMethod

export const SessionKeyError = createError(
  'FST_SESSION_KEY',
  'config must have an issuer with an identifier',
  500
)

export const SessionValueError = createError(
  'FST_SESSION_VALUE',
  'did not find expected authorization request details in req.session["%s"]',
  500
)

export const SupportedMethodError = createError(
  'FST_SUPPORTED_METHOD',
  'neither code_challenge_method supported by the client is supported by the issuer',
  500
)

const resolveRedirectUri = (config: Configuration): string | undefined => {
  const redirectUris = config.clientMetadata().redirect_uris
  if (!Array.isArray(redirectUris) || redirectUris.length !== 1) {
    return undefined
  }
  const value = redirectUris[0]
  return typeof value === 'string' ? value : undefined
}

const resolveSupportedMethod = (config: Configuration): string => {
  const supportedMethods =
    config.serverMetadata().code_challenge_methods_supported

  if (supportedMethods === undefined || supportedMethods.includes('S256')) {
    return 'S256'
  }
  if (supportedMethods.includes('plain')) {
    return 'plain'
  }
  throw new SupportedMethodError()
}

const resolveSessionKey = (config: Configuration): string => {
  const issuer = config.serverMetadata().issuer
  if (issuer === undefined) {
    throw new SessionKeyError()
  }
  return `oidc:${new URL(issuer).hostname}`
}

import { resolveParameters } from './utils.js'

export const openIDLoginHandlerFactory: OpenIDLoginHandlerFactory = (
  config,
  options
) => {
  const sessionKey = options?.sessionKey ?? resolveSessionKey(config)
  const usePKCE =
    options?.usePKCE !== undefined
      ? options.usePKCE === true
        ? resolveSupportedMethod(config)
        : options.usePKCE
      : false

  const { verify, write, tokenEndpoint } = { ...options }

  return async function openIDLoginHandler(request, reply) {
    const params = await resolveParameters(options?.parameters, request, reply)
    const redirect_uri = params?.redirect_uri ?? resolveRedirectUri(config)

    // Check if this is a callback (has code or error in query)
    const query = request.query as Record<string, string>
    const isCallback = query.code !== undefined || query.error !== undefined

    // #region authentication request
    if (!isCallback) {
      const state = randomState()
      const nonce = randomNonce()

      const parameters: Record<string, string> = {
        scope: 'openid',
        state,
        nonce,
        redirect_uri: redirect_uri ?? '',
        response_type: 'code',
        ...params
      }

      const callbackChecks: CallbackChecks = {
        state,
        nonce
      }

      if (usePKCE !== false) {
        const verifier = randomPKCECodeVerifier()
        callbackChecks.pkceCodeVerifier = verifier

        switch (usePKCE) {
          case 'S256':
            parameters.code_challenge =
              await calculatePKCECodeChallenge(verifier)
            parameters.code_challenge_method = 'S256'
            break
          case 'plain':
            parameters.code_challenge = verifier
            parameters.code_challenge_method = 'plain'
            break
        }
      }

      request.session.set(sessionKey, callbackChecks)
      const authUrl = buildAuthorizationUrl(config, parameters)
      request.log.trace('OpenID login redirect')
      return await reply.redirect(authUrl.href)
    }
    // #endregion

    // #region authentication response
    const callbackChecks: CallbackChecks = request.session.get(sessionKey)
    if (
      callbackChecks === undefined ||
      Object.keys(callbackChecks).length === 0
    ) {
      throw new SessionValueError(sessionKey)
    }

    request.session.set(sessionKey, undefined)

    // Build the current URL from the request
    // Always include port to match the original redirect_uri
    const currentUrl = new URL(
      `${request.protocol}://${request.hostname}:${request.socket.localPort}${request.url}`
    )

    const tokenset = await authorizationCodeGrant(
      config,
      currentUrl,
      {
        pkceCodeVerifier: callbackChecks.pkceCodeVerifier,
        expectedState: callbackChecks.state,
        expectedNonce: callbackChecks.nonce
      },
      await resolveParameters(tokenEndpoint?.parameters, request, reply),
      tokenEndpoint?.options
    )

    const verified =
      verify !== undefined ? await openIDJWTVerify(tokenset, verify) : undefined
    request.log.trace('OpenID login callback')
    return await write?.call(this, request, reply, tokenset, verified)
    // #endregion
  }
}
