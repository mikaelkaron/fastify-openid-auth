import type { Server } from 'node:http'
import type { Middleware, Next, ParameterizedContext } from 'koa'
import type { Adapter, AdapterPayload, ClientMetadata } from 'oidc-provider'
import Provider from 'oidc-provider'
import { getPrivateJWKS, getTestKeys } from './keys.ts'

export class DynamicMiddleware {
  stack: Array<(ctx: ParameterizedContext, next: Next) => Promise<void>> = []

  middleware: Middleware = async (ctx, next) => {
    let i = 0
    const run = async () =>
      i < this.stack.length ? this.stack[i++](ctx, run) : next()
    return run()
  }

  add(fn: Middleware) {
    this.stack.push(fn)
  }

  remove(fn: Middleware) {
    this.stack = this.stack.filter((m) => m !== fn)
  }
}

export class TestAdapter implements Adapter {
  static memory = new Map<string, AdapterPayload & { expiresAt: number }>()
  public name: string

  constructor(name: string) {
    this.name = name
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn: number) {
    TestAdapter.memory.set(id, {
      ...payload,
      expiresAt: Date.now() + expiresIn * 1000
    })
  }

  async find(id: string) {
    const entry = TestAdapter.memory.get(id)
    if (!entry) return undefined

    if (entry.expiresAt < Date.now()) {
      TestAdapter.memory.delete(id)
      return undefined
    }
    return entry
  }

  async destroy(id: string) {
    TestAdapter.memory.delete(id)
  }

  async revokeByGrantId(grantId: string) {
    for (const [key, value] of TestAdapter.memory) {
      if (value.grantId === grantId) TestAdapter.memory.delete(key)
    }
  }

  async consume(id: string) {
    const entry = TestAdapter.memory.get(id)
    if (entry) entry.consumed = Math.floor(Date.now() / 1000)
  }

  async findByUserCode(userCode: string) {
    for (const value of TestAdapter.memory.values()) {
      if (value.userCode === userCode) {
        return value
      }
    }
    return undefined
  }

  async findByUid(uid: string) {
    for (const value of TestAdapter.memory.values()) {
      if (value.uid === uid) {
        return value
      }
    }
    return undefined
  }
}

export interface TestProvider {
  issuer: string
  provider: InstanceType<typeof Provider>
  server: Server
  stop: () => Promise<void>
  testMiddleware: DynamicMiddleware
}

export interface TestProviderOptions {
  port?: number
  clients?: ClientMetadata[]
}

export async function createTestProvider(
  options: TestProviderOptions = {}
): Promise<TestProvider> {
  const port = options.port ?? 3000
  const issuer = `http://localhost:${port}`

  const keys = await getTestKeys()
  const provider = new Provider(issuer, {
    clients: options.clients ?? [
      {
        client_id: 'test-client',
        client_secret: 'test-secret',
        redirect_uris: ['http://localhost:8080/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token']
      }
    ],
    adapter: TestAdapter,
    jwks: getPrivateJWKS(keys),
    features: {
      devInteractions: { enabled: false }
    },
    pkce: {
      required: () => false
    },
    findAccount: async (_ctx, id) => ({
      accountId: id,
      claims: async () => ({ sub: id })
    }),
    // Allow insecure HTTP for testing
    cookies: {
      keys: ['test-cookie-key']
    }
  })

  // Allow HTTP for testing
  provider.proxy = true

  // Attach dynamic middleware
  const testMiddleware = new DynamicMiddleware()
  provider.use(testMiddleware.middleware)

  const server = await new Promise<Server>((resolve) => {
    const srv = provider.listen(port, () => resolve(srv))
  })

  const stop = async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()))
    })
  }

  return { issuer, provider, server, stop, testMiddleware }
}
