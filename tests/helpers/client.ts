import { Issuer, type Client } from 'openid-client'

export interface CreateClientOptions {
  issuer: string
  clientId: string
  clientSecret?: string
  redirectUris?: string[]
  responseTypes?: string[]
}

export async function createTestClient(
  options: CreateClientOptions
): Promise<Client> {
  const issuer = await Issuer.discover(options.issuer)

  const client = new issuer.Client({
    client_id: options.clientId,
    client_secret: options.clientSecret ?? 'test-secret',
    redirect_uris: options.redirectUris ?? ['http://localhost:8080/callback'],
    response_types: options.responseTypes ?? ['code']
  })

  return client
}
