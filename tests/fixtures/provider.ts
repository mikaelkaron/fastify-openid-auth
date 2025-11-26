import type { Server } from 'node:http'
import Provider from 'oidc-provider'
import { getTestKeys } from './keys.js'

export interface TestProvider {
  issuer: string
  provider: InstanceType<typeof Provider>
  server: Server
  stop: () => Promise<void>
}

export interface TestProviderOptions {
  port?: number
  clients?: Array<{
    client_id: string
    client_secret?: string
    redirect_uris: string[]
    response_types?: string[]
    grant_types?: string[]
  }>
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
    jwks: { keys: [keys.jwk] },
    features: {
      devInteractions: { enabled: false }
    },
    pkce: {
      methods: ['S256', 'plain'],
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

  const server = await new Promise<Server>((resolve) => {
    const srv = provider.listen(port, () => resolve(srv))
  })

  const stop = async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()))
    })
  }

  return { issuer, provider, server, stop }
}
