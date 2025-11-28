import Fastify, { type FastifyInstance } from 'fastify'
import type { AuthorizationChecks, OpenIDSession } from '../../src/index.ts'

export const createTestSession = <T extends AuthorizationChecks>(
  initial?: T
): OpenIDSession<T> => {
  let store: T | undefined = initial

  const get: OpenIDSession<T>['get'] = (_request, _reply) => {
    return store
  }

  const set: OpenIDSession<T>['set'] = (_request, _reply, value) => {
    store = value
  }

  return { get, set }
}

export async function createTestFastify(): Promise<FastifyInstance> {
  return Fastify({
    logger: false
  })
}
