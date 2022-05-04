/* eslint-disable semi */
import IAccessToken from "./IAccessToken";

export default interface IClient {
    clientId: string;
    clientSecret?: string;
    redirectUris?: string[];
    scope: string[];
    public?: boolean;
    enabled: boolean;
    accessTokens?: IAccessToken[];
    refreshTokens?: string[];
};