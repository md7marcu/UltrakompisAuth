import * as jose from "node-jose";

export default async function createJwk(cert: Buffer): Promise<any> {
    return await jose.JWK.asKey(cert, "pem");
}
