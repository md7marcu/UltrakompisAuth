import decodeBase64 from "../helpers/DecodeBase64";
import IBasicAuth from "../interfaces/IBasicAuth";

export default function getBasicAuth(authorizationHeader: string): IBasicAuth {
    if (authorizationHeader) {
        let encodedData = authorizationHeader.split(" ")[1] || "";
        let decodedData = decodeBase64(encodedData);
        let splitHeader = decodedData.split(":");

        if (splitHeader && splitHeader[0] && splitHeader[1]) {
            return {user: splitHeader[0], password: splitHeader[1]};
        }
    }
    return undefined;
}