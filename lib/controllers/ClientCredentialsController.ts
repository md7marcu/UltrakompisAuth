import * as Debug from "debug";
import Db from "../db/db";
import IClient from "interfaces/IClient";
import { config } from "node-config-ts";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import getRandomString from "../helpers/GetRandomString";
import signToken from "../helpers/SignToken";
import IClientCredentialToken from "../interfaces/IClientCredentialToken";
import IBasicAuth from "../interfaces/IBasicAuth";
import verifyClient from "../helpers/VerifyClient";
import getBasicAuth from "../helpers/GetBasicAuth";
const debug = Debug("AuthServer:clientAuthController:");

export class ClientCredentialsController {

    public getTokens = async(db: Db, authorizationHeader: string, key: Buffer): Promise<IClientCredentialToken> => {                
        let client: IClient;
        let clientAuth: IBasicAuth;

        if (clientAuth = getBasicAuth(authorizationHeader)){
            client = await db.getClient(clientAuth.user);

            if (!verifyClient(client, clientAuth.user, clientAuth.password)) {
                return undefined;
            }
            let tokenPayload = await this.buildAccessToken(client.clientId, client.scope);
            let accessToken = signToken(tokenPayload, key);
            db.saveAccessToken(accessToken, clientAuth.user);            
            let refreshToken = getRandomString(config.settings.refreshTokenLength);
            db.saveClientRefreshToken(refreshToken, clientAuth.user);
            
            return { 
                    access_token: accessToken,
                    token_type: config.settings.bearerTokenType, 
                    expires_in: config.settings.expiryTime, 
                    refresh_token: refreshToken,
                    scope: client.scope
            };
        }
        return undefined;
    }

    private buildAccessToken = async (clientId: string, scope: string[]): Promise<IVerifyOptions> => {
        let payload = {
            iss: config.settings.issuer,
            aud: config.settings.audience,
            sub: clientId,
            exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
            iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
            scope: scope,
        };

        return payload;
    }
}