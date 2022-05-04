import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { config } from "node-config-ts";
import IUser from "../interfaces/IUser";
import getRandomString from "./GetRandomString";
import { Guid } from "guid-typescript";

export async function buildUserAccessToken(scope: string[], clientId: string, user: IUser): Promise<IVerifyOptions> {
    let payload = {
        iss: config.settings.issuer,
        aud: [config.settings.audience, clientId],
        sub: user.userId,
        exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
        iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
        scope: scope,
        email: user?.email,
        claims: user?.claims,
    };

    if (config.settings.addNonceToToken) {
        (payload as any).jti = getRandomString(16);
    }
    return payload;
}

export async function buildClientAccessToken(clientId: string, scope: string[]): Promise<IVerifyOptions> {
    let payload = {
        iss: config.settings.issuer,
        aud: [config.settings.audience, clientId],
        sub: clientId,
        exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
        iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
        scope: scope,
    };

    return payload;
}