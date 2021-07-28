import * as Debug from "debug";
import Db from "../db/db";
import IClient from "interfaces/IClient";
import { config } from "node-config-ts";
import getRandomString from "../helpers/GetRandomString";
import signToken from "../helpers/SignToken";
import IClientCredentialToken from "../interfaces/IClientCredentialToken";
import IBasicAuth from "../interfaces/IBasicAuth";
import verifyClient from "../helpers/VerifyClient";
import getBasicAuth from "../helpers/GetBasicAuth";
import { buildClientAccessToken } from "../helpers/BuildAccessToken";
const debug = Debug("AuthServer:ClientCredentialsController:");

export class ClientCredentialsController {

    public getTokens = async(db: Db, authorizationHeader: string, key: Buffer): Promise<IClientCredentialToken> => {
        let client: IClient;
        let clientAuth: IBasicAuth = getBasicAuth(authorizationHeader);

        if (clientAuth) {
            client = await db.getClient(clientAuth.user);

            if (!verifyClient(client, clientAuth.user, clientAuth.password)) {
                return undefined;
            }
            let tokenPayload = await buildClientAccessToken(client.clientId, client.scope);
            let accessToken = signToken(tokenPayload, key);
            db.saveAccessToken(accessToken, clientAuth.user);
            let refreshToken = getRandomString(config.settings.refreshTokenLength);
            db.saveClientRefreshToken(refreshToken, clientAuth.user);

            return {
                    access_token: accessToken,
                    token_type: config.settings.bearerTokenType,
                    expires_in: config.settings.expiryTime,
                    refresh_token: refreshToken,
                    scope: client.scope,
            };
        }
        return undefined;
    }
}