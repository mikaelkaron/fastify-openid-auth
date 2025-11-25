/* eslint-disable @typescript-eslint/naming-convention */
import createError from '@fastify/error'
import type { FastifyReply, FastifyRequest, RouteHandlerMethod } from 'fastify'
import openIDClient, {
  type AuthorizationParameters,
  type CallbackExtras,
  type Client,
  type Issuer,
  type OpenIDCallbackChecks
} from 'openid-client'
import type { OpenIDWriteTokens } from './types.js'
import { type OpenIDVerifyOptions, openIDJWTVerify } from './verify.js'

declare module 'fastify' {
  interface FastifyRequest {
    session: Session
  }

  type Session<T = SessionData> = Partial<T> & {
    // eslint-disable-next-line @typescript-eslint/method-signature-style
    get<Key extends keyof T>(key: Key): T[Key] | undefined
    // eslint-disable-next-line @typescript-eslint/method-signature-style
    set<Key extends keyof T>(key: Key, value: T[Key] | undefined): void
  }
}

// biome-ignore lint/suspicious/noExplicitAny: User can supply `any` type in the app
export type SessionData = Record<string, any>

export interface OpenIDLoginHandlerOptions {
  parameters?: AuthorizationParameters | ((request: FastifyRequest, reply: FastifyReply) => AuthorizationParameters)
  extras?: CallbackExtras
  usePKCE?: boolean | 'plain' | 'S256'
  sessionKey?: string
  verify?: OpenIDVerifyOptions
  write?: OpenIDWriteTokens
}

export type OpenIDLoginHandlerFactory = (
  client: Client,
  options?: OpenIDLoginHandlerOptions
) => RouteHandlerMethod

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

const { generators } = openIDClient

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
  }
  if (supportedMethods.includes('plain')) {
    return 'plain'
  }
  throw new SupportedMethodError()
}

const resolveSessionKey = (issuer: Issuer): string => {
  if (issuer.metadata.issuer === undefined) {
    throw new SessionKeyError()
  }
  return `oidc:${new URL(issuer.metadata.issuer).hostname}`
}

export const openIDLoginHandlerFactory: OpenIDLoginHandlerFactory = (
  client,
  options
) => {
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

  const { verify, extras, write } = { ...options }

  return async function openIDLoginHandler(request, reply) {
    const params = typeof options?.parameters === 'function' ? options.parameters(request, reply) : options?.parameters 
      const redirect_uri =
    params?.redirect_uri !== undefined
      ? params.redirect_uri
      : resolveRedirectUri(client)
    const callbackParams = client.callbackParams(request.raw)

    // #region authentication request
    if (Object.keys(callbackParams).length === 0) {
      const response_type =
        params?.response_type !== undefined
          ? params.response_type
          : resolveResponseType(client)
      const parameters = {
        scope: 'openid',
        state: generators.random(),
        redirect_uri,
        response_type,
        ...params
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
      request.log.trace('OpenID login redirect')
      return await reply.redirect(client.authorizationUrl(parameters))
    }
    // #endregion

    // #region authentication response
    const callbackChecks: OpenIDCallbackChecks = request.session.get(sessionKey)
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
      extras
    )
    const verified =
      verify !== undefined ? await openIDJWTVerify(tokenset, verify) : undefined
    request.log.trace('OpenID login callback')
    return await write?.call(this, request, reply, tokenset, verified)
    // #endregion
  }
}
