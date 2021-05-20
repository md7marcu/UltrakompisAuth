import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { config } from "node-config-ts";
import IUser from "../interfaces/IUser";

// Create an id token for OpenId Connect flow
export default async function buildIdToken(email: string, clientId: string, user: IUser): Promise<IVerifyOptions> {
    return {
        iss: config.settings.issuer,
        sub: user?.email,
        aud: clientId,
        exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
        iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
        auth_time: user?.lastAuthenticated,
        nonce: user?.nonce,
    };
}
