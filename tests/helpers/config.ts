import {
  allowInsecureRequests,
  type Configuration,
  discovery
} from 'openid-client'

export interface CreateConfigOptions {
  issuer: string
  clientId: string
  clientSecret?: string
  redirectUris?: string[]
}

export async function createTestConfig(
  options: CreateConfigOptions
): Promise<Configuration> {
  const issuerUrl = new URL(options.issuer)

  const config = await discovery(
    issuerUrl,
    options.clientId,
    options.clientSecret ?? 'test-secret',
    undefined,
    {
      // Allow HTTP for local testing
      execute: [allowInsecureRequests]
    }
  )

  return config
}
