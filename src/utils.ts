import type { FastifyReply, FastifyRequest } from 'fastify'

export type ParametersFunction<T extends Record<string, string>> = (
  request: FastifyRequest,
  reply: FastifyReply
) => T | PromiseLike<T>

export async function resolveParameters<T extends Record<string, string>>(
  parameters: T | ParametersFunction<T> | undefined,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<T | undefined> {
  return typeof parameters === 'function'
    ? parameters(request, reply)
    : parameters
}
