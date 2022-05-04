import * as naclUtil from "tweetnacl-util";
import sha256 from "fast-sha256";

export default function verifyCodeChallenge(codeChallenge: any, reqCodeChallenge: any): boolean {
    const encodedString = naclUtil.decodeUTF8(reqCodeChallenge);
    const sha256String = sha256(encodedString);
    const base64String = naclUtil.encodeBase64(sha256String).replace(/\=+$/, "");

    return base64String.replace(/\+/g, "-").replace(/\//g, "_") === codeChallenge;
}
