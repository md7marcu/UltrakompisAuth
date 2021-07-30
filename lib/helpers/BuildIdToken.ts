import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { config } from "node-config-ts";
import IUser from "../interfaces/IUser";
import { Guid } from "guid-typescript";

// Create an id token for OpenId Connect flow
export default async function buildIdToken(email: string, clientId: string, user: IUser): Promise<IVerifyOptions> {
    return {
        iss: config.settings.issuer,
        sub: Guid.create().toString(),
        aud: clientId,
        exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
        iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
        auth_time: user?.lastAuthenticated,
        email: user?.email,
        nonce: user?.nonce,
    };
}
