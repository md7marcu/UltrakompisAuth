import * as Debug from "debug";
import Db from "../db/db";
import IClient from "interfaces/IClient";
import { config } from "node-config-ts";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import signToken from "../helpers/SignToken";
import ITokenExchangeToken from "../interfaces/ITokenExchangeToken";
import IBasicAuth from "../interfaces/IBasicAuth";
import verifyClient from "../helpers/VerifyClient";
import getBasicAuth from "../helpers/GetBasicAuth";
import verifyToken from "../helpers/VerifyToken";
import { decode } from "jsonwebtoken";
const debug = Debug("AuthServer:clientAuthController:");

export class TokenExchangeController {

    public getTokens = async(db: Db, authorizationHeader: string, body: any, key: Buffer, cert: Buffer): Promise<ITokenExchangeToken> => {                
        let client: IClient;
        let clientAuth: IBasicAuth;

        if (!authorizationHeader || !body) {
            return undefined; // 401
        }

        if (clientAuth = getBasicAuth(authorizationHeader)){
            client = await db.getClient(clientAuth.user);

            if (!verifyClient(client, clientAuth.user, clientAuth.password)) {
                return undefined; // 401
            }

            if (!body.subject_token || body.subject_token_type !== config.settings.tokenExchangeSubjectType) {
                return undefined; // 400
            }
            let subjectToken = body.subject_token;

            if (!verifyToken(subjectToken, cert)) {
                debug(`Failed to verify subject_token ${subjectToken}`);

                return undefined; // 400
            }
            let decodedSubjectToken = (decode(subjectToken) as any);
            // If the token has a may act - the may act field need to match the actor (client id)
            if (decodedSubjectToken.may_act && !this.verifyMayAct(decodedSubjectToken.may_act.sub, client.clientId)) {
                return undefined; // 401
            }

            let tokenPayload = this.buildTokenExchangeToken(decodedSubjectToken.sub, client.clientId, decodedSubjectToken.scope);
            let accessToken = signToken(tokenPayload, key);

            return {
                access_token: accessToken,
                issued_token_type: config.settings.tokenExchangeSubjectType,
                token_type: config.settings.bearerTokenType,
                expires_in: config.settings.tokenExchangeExpiryTime, 
                scope: decodedSubjectToken.scope,
            }
        }
        return undefined; // 401
    }

    private verifyMayAct = (sub: string, clientId: string): boolean => {
        return sub === clientId;
    }

    private buildTokenExchangeToken = (subject: string, clientId: string, scopes: string[]): IVerifyOptions => {
        let payload = {
            iss: config.settings.issuer,
            aud: config.settings.audience, //config.settings.microserviceAudience
            sub: subject,
            exp: Math.floor(Date.now() / 1000) + config.settings.tokenExchangeExpiryTime,
            iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
            act: { 
                sub: clientId 
            },
            scope: scopes,
        };
        return payload;
    }
}