/* tslint:disable */
/* eslint-disable */
declare module "node-config-ts" {
  interface IConfig {
    settings: Settings
    wellKnown: WellKnown
  }
  interface WellKnown {
    issuer: string
    authorization_endpoint: string
    device_authorization_endpoint: string
    token_endpoint: string
    userinfo_endpoint: string
    jwks_uri: string
    response_types_supported: string[]
    subject_types_supported: string[]
    scopes_supported: string[]
    token_endpoint_auth_methods_supported: string[]
    claims_supported: string[]
    code_challenge_methods_supported: string[]
    grant_types_supported: string[]
  }
  interface Settings {
    issuer: string
    audience: string
    subject: string
    algorithm: string
    authorizationEndpoint: string
    accessTokenEndpoint: string
    aliveEndpoint: string
    jwksEndpoint: string
    scope: string
    verifyRedirectUrl: boolean
    verifyClientId: boolean
    verifyClientIdOnRefreshToken: boolean
    verifyScope: boolean
    verifyCode: boolean
    validateScope: boolean
    clearAuthorizationCode: boolean
    clearRequestId: boolean
    authorizationCodeLength: number
    accessTokenLength: number
    removeExpiredAccessTokens: boolean
    removeExpiredRefreshTokens: boolean
    removeExpiredIdTokens: boolean
    refreshTokenLength: number
    corsWhitelist: string[]
    expiryTime: number
    tokenExchangeExpiryTime: number
    createdTimeAgo: number
    addNonceToAccessToken: boolean
    saveAccessToken: boolean
    authorizationCodeGrant: string
    clientCredentialsGrant: string
    refreshTokenGrant: string
    tokenExchangeGrant: string
    bearerTokenType: string
    tokenExchangeSubjectType: string
    verifyState: boolean
    useMongo: boolean
    usePkce: boolean
    overrideId: string
    clients: Client[]
    users: User[]
    serverCert: string
    jwkAlgorithm: string
    jwkUse: string
  }
  interface User {
    userId: string
    password: string
    email: string
    name: string
  }
  interface Client {
    clientId: string
    clientSecret?: string
    redirectUris: string[]
    scope: string[]
    public?: boolean
  }
  export const config: Config
  export type Config = IConfig
}
