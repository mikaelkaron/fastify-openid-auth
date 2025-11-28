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
import type { OpenIDSession, OpenIDWriteTokens, Resolvable } from './types.js'
import { resolveParameters } from './utils.js'
import { type OpenIDVerifyOptions, openIDJWTVerify } from './verify.js'

export type AuthorizationParameters = Record<string, string>

export type AuthorizationTokenEndpointParameters = Record<string, string>

export type AuthorizationTokenEndpoint = {
  parameters?: Resolvable<AuthorizationTokenEndpointParameters>
  options?: AuthorizationCodeGrantOptions
}

export type AuthorizationChecks = {
  state?: string
  nonce?: string
  pkceCodeVerifier?: string
}

export interface OpenIDLoginHandlerOptions {
  parameters?: Resolvable<AuthorizationParameters>
  usePKCE?: boolean | 'plain' | 'S256'
  tokenEndpoint?: AuthorizationTokenEndpoint
  verify?: OpenIDVerifyOptions
  write?: OpenIDWriteTokens
  session: OpenIDSession<AuthorizationChecks>
}

export type OpenIDLoginHandlerFactory = (
  config: Configuration,
  options: OpenIDLoginHandlerOptions
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

export const openIDLoginHandlerFactory: OpenIDLoginHandlerFactory = (
  config,
  options
) => {
  const usePKCE =
    options.usePKCE !== undefined
      ? options.usePKCE === true
        ? resolveSupportedMethod(config)
        : options.usePKCE
      : false

  const { verify, write, tokenEndpoint, session } = { ...options }

  return async function openIDLoginHandler(request, reply) {
    const params = await resolveParameters(options.parameters, request, reply)
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

      const callbackChecks: AuthorizationChecks = {
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

      session.set(request, reply, callbackChecks)

      const authUrl = buildAuthorizationUrl(config, parameters)
      request.log.trace('OpenID login redirect')
      return await reply.redirect(authUrl.href)
    }
    // #endregion

    // #region authentication response
    const callbackChecks = session.get(request, reply)
    if (
      callbackChecks === undefined ||
      Object.keys(callbackChecks).length === 0
    ) {
      throw new SessionValueError()
    }

    session.set(request, reply, undefined)

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
