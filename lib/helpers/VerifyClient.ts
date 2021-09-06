import IClient from "interfaces/IClient";
import * as Debug from "debug";
const debug = Debug("AuthServer:clientAuthController:");

export default function verifyClient(client: IClient, clientId: string, clientSecret: string): boolean {
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