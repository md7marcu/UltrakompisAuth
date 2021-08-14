import { VerifyOptions, verify } from "jsonwebtoken";
import { config } from "node-config-ts";
import { pki }from "node-forge";
import * as Debug from "debug";
const debug = Debug("VerifyToken");

export default function verifyToken(token: string, serverCert: Buffer): any {
    let bearerToken = getTokenValue(token);
    let publicKey = pki.publicKeyToPem(pki.certificateFromPem(serverCert).publicKey);
    debug(`Server public key: ${JSON.stringify(publicKey)}`);

    let decodedToken;
    try {
        let options = getVerifyOptions();
        decodedToken = verify(bearerToken, publicKey, options);
    } catch (err) {
        debug(`Verifying accessToken failed: ${err.message}`);

        return "";
    }
    return decodedToken;
}

// Remove "Bearer " from token if it exists
const getTokenValue = (token: string): string => {
    return token?.replace("Bearer ", "");
};

// Decide what to verify in the token
const getVerifyOptions = (): VerifyOptions => {
    let verifyOptions: VerifyOptions = {};

    if (config.verifyIssuer) {
        verifyOptions.issuer = config.settings.issuer;
    }
    if (config.verifyAudience) {
        verifyOptions.audience = config.settings.audience;
    }
    verifyOptions.ignoreNotBefore = config.settings.ignoreNotBefore;
    verifyOptions.ignoreExpiration = config.settings.ignoreExpiration;
    verifyOptions.algorithms = [config.settings.algorithm];

    return verifyOptions;
}