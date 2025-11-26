import Fastify, { type FastifyInstance } from 'fastify'

export interface MockSession {
  data: Map<string, unknown>
  get<T>(key: string): T | undefined
  set<T>(key: string, value: T | undefined): void
}

export function createMockSession(): MockSession {
  const data = new Map<string, unknown>()
  return {
    data,
    get<T>(key: string): T | undefined {
      return data.get(key) as T | undefined
    },
    set<T>(key: string, value: T | undefined): void {
      if (value === undefined) {
        data.delete(key)
      } else {
        data.set(key, value)
      }
    }
  }
}

export interface TestFastifyOptions {
  session?: MockSession
}

export async function createTestFastify(
  options: TestFastifyOptions = {}
): Promise<FastifyInstance> {
  const session = options.session ?? createMockSession()

  const fastify = Fastify({
    logger: false
  })

  // Decorate request with mock session
  fastify.decorateRequest('session', null)

  fastify.addHook('onRequest', async (request) => {
    request.session = session
  })

  return fastify
}
