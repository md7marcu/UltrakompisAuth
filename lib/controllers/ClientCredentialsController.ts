import * as Debug from "debug";
import Db from "../db/db";
import IClient from "interfaces/IClient";
import { config } from "node-config-ts";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import getRandomString from "../helpers/GetRandomString";
import signToken from "../helpers/SignToken";
import IClientCredentialToken from "../interfaces/IClientCredentialToken";
const debug = Debug("AuthServer:clientAuthController:");

export class ClientCredentialsController {

    public getTokens = async(db: Db, authorizationHeader: string): Promise<IClientCredentialToken> => {                
        let encodedData = authorizationHeader?.split(" ")[1];
        let decodedData = this.decodeBase64(encodedData);
        let splitHeader = decodedData.split(":");
        let client: IClient;

        if (splitHeader && splitHeader[0] && splitHeader[1]) {
            let clientId = splitHeader[0];
            let clientSecret = splitHeader[1];
            client = await db.getClient(clientId);

            if (!this.verifyClient(client, clientId, clientSecret)) {
                return undefined;
            }
            let tokenPayload = await this.buildAccessToken(client.clientId, client.scopes);
            let accessToken = signToken(tokenPayload);
            db.saveAccessToken(accessToken, clientId);            
            let refreshToken = getRandomString(config.settings.refreshTokenLength);
            db.saveClientRefreshToken(refreshToken, clientId);
            
            return { 
                    access_token: accessToken,
                    token_type: config.settings.clientCredentialsTokenType, 
                    expires_in: config.settings.expiryTime, 
                    refresh_token: refreshToken,
                    scope: client.scopes
            };
        }
        return undefined;
    }

    private decodeBase64 = (encodded: string): string => {
        const buffer = Buffer.from(encodded, "base64")

        return buffer.toString("utf-8");;
    }

    private verifyClient = async(client: IClient, clientId: string, clientSecret: string): Promise<boolean> => {

        if (!client) {
            debug(`Could not find client: ${clientId}`);

            return false;
        }

        if (client.clientSecret !== clientSecret) {
            debug("Invalid client secret: <removed>");

            return false;    
        }

        return true;
    }

    private buildAccessToken = async (clientId: string, scopes: string[]): Promise<IVerifyOptions> => {
        let payload = {
            iss: config.settings.issuer,
            aud: config.settings.audience,
            sub: clientId,
            exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
            iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
            scope: scopes,
        };

        return payload;
    }
}