/* eslint-disable @typescript-eslint/naming-convention */
import { type RouteHandlerMethod } from 'fastify'
import createError from '@fastify/error'
import {
  type AuthorizationParameters,
  type CallbackExtras,
  type Client,
  generators,
  type Issuer,
  type OpenIDCallbackChecks
} from 'openid-client'
import { type OpenIDWriteTokens } from './types'

declare module 'fastify' {
  interface FastifyRequest {
    session: Session
  }

  interface Session {
    // eslint-disable-next-line @typescript-eslint/method-signature-style
    get<Key extends keyof SessionData>(key: Key): SessionData[Key] | undefined
    // eslint-disable-next-line @typescript-eslint/method-signature-style
    set<Key extends keyof SessionData>(key: Key, value: SessionData[Key] | undefined): void
  }
}

export type SessionData = Record<string, any>

export interface OpenIDLoginHandlerOptions {
  parameters?: AuthorizationParameters
  extras?: CallbackExtras
  usePKCE?: boolean | 'plain' | 'S256'
  sessionKey?: string
  write?: OpenIDWriteTokens
}

export const SessionKeyError = createError(
  'FST_SESSION_KEY',
  'client must have an issuer with an identifier',
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

const resolveResponseType = (client: Client): string | undefined => {
  const { length, 0: value } = client.metadata.response_types ?? []

  if (length === 1) {
    return value
  }

  return undefined
}

const resolveRedirectUri = (client: Client): string | undefined => {
  const { length, 0: value } = client.metadata.redirect_uris ?? []

  if (length === 1) {
    return value
  }

  return undefined
}

const resolveSupportedMethod = (issuer: Issuer): string => {
  const supportedMethods = Array.isArray(
    issuer.code_challenge_methods_supported
  )
    ? issuer.code_challenge_methods_supported
    : false

  if (supportedMethods === false || supportedMethods.includes('S256')) {
    return 'S256'
  } else if (supportedMethods.includes('plain')) {
    return 'plain'
  } else {
    throw new SupportedMethodError()
  }
}

const resolveSessionKey = (issuer: Issuer): string => {
  if (issuer.metadata.issuer === undefined) {
    throw new SessionKeyError()
  }
  return `oidc:${new URL(issuer.metadata.issuer).hostname}`
}

export const openIDLoginHandlerFactory = (
  client: Client,
  options?: OpenIDLoginHandlerOptions
): RouteHandlerMethod => {
  const redirect_uri =
    options?.parameters?.redirect_uri !== undefined
      ? options.parameters.redirect_uri
      : resolveRedirectUri(client)
  const sessionKey =
    options?.sessionKey !== undefined
      ? options.sessionKey
      : resolveSessionKey(client.issuer)
  const usePKCE =
    options?.usePKCE !== undefined
      ? options.usePKCE === true
        ? resolveSupportedMethod(client.issuer)
        : options.usePKCE
      : false

  const { write } = { ...options }

  return async function openIDLoginHandler (request, reply) {
    const callbackParams = client.callbackParams(request.raw)

    // #region authentication request
    if (Object.keys(callbackParams).length === 0) {
      const response_type =
        options?.parameters?.response_type !== undefined
          ? options.parameters.response_type
          : resolveResponseType(client)
      const parameters = {
        scope: 'openid',
        state: generators.random(),
        redirect_uri,
        response_type,
        ...options?.parameters
      }
      if (
        parameters.nonce === undefined &&
        parameters.response_type === 'code'
      ) {
        parameters.nonce = generators.random()
      }
      const callbackChecks: OpenIDCallbackChecks = (({
        nonce,
        state,
        max_age,
        response_type
      }) => ({ nonce, state, max_age, response_type }))(parameters)
      if (usePKCE !== false && parameters.response_type === 'code') {
        const verifier = generators.random()

        callbackChecks.code_verifier = verifier

        switch (usePKCE) {
          case 'S256':
            parameters.code_challenge = generators.codeChallenge(verifier)
            parameters.code_challenge_method = 'S256'
            break
          case 'plain':
            parameters.code_challenge = verifier
            break
        }
      }

      request.session.set(sessionKey, callbackChecks)

      return await reply.redirect(client.authorizationUrl(parameters))
    }
    // #endregion

    // #region authentication response
    const callbackChecks: OpenIDCallbackChecks =
      request.session.get(sessionKey)
    if (
      callbackChecks === undefined ||
      Object.keys(callbackChecks).length === 0
    ) {
      throw new SessionValueError(sessionKey)
    }

    request.session.set(sessionKey, undefined)

    const tokenset = await client.callback(
      redirect_uri,
      callbackParams,
      callbackChecks,
      options?.extras
    )
    return await write?.call(this, request, reply, tokenset)
    // #endregion
  }
}
