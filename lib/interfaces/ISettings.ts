export default interface ISettings {
    overrideId: String;
    issuer: String;
    audience: String;
    subject: String;
    algorithm: String;
    authorizationEndpoint: String;
    accessTokenEndpoint: String;
    aliveEndpoint: String;
    scope: String;
    verifyRedirectUrl: Boolean;
    verifyClientId: Boolean;
    verifyScope: Boolean;
    verifyCode: Boolean;
    validateScope: Boolean;
    clearAuthorizationCode: Boolean;
    clearRequestId: Boolean;
    authorizationCodeLength: Number;
    accessTokenLength: Number;
    refreshTokenLength: Number;
    clients: [
        {
            clientId: String;
            clientSecret: String;
            redirectUris: [String];
            scope: [String];
        }
    ];
    users: [
        {
            userId: String;
            password: String;
            email: String;
            name: String;
        }
    ];
    expiryTime: Number;
    tokenExchangeExpiryTime: Number;
    createdTimeAgo: Number;
    addNonceToAccessToken: Boolean;
    saveAccessToken: Boolean;
    authorizationCodeGrant: String;
    clientCredentialsGrant: String;
    refreshTokenGrant: String;
    tokenExchangeGrant: String;
    bearerTokenType: string;
    tokenExchangeSubjectType: string;
    verifyState: Boolean;
    useMongo: Boolean;
    serverCert: string
}