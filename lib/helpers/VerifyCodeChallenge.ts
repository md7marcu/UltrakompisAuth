import * as naclUtil from "tweetnacl-util";
import sha256 from "fast-sha256";

export default function VerifyCodeChallenge(codeChallenge: any, reqCodeChallenge: any): boolean {
    const encodedString = naclUtil.decodeUTF8(reqCodeChallenge);
    const sha256String = sha256(encodedString);
    const base64String = naclUtil.encodeBase64(sha256String);

    return base64String === codeChallenge;
}
