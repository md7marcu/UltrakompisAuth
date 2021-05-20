import { Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ClientRoutes:");
import Db from "../db/db";

export class ClientController {

    public async addClient(req: Request, res: Response, database: Db ) {
        debug(`Adding Client: ${JSON.stringify(req.body)}`);
        let client = await database.addClient(req?.body?.clientId, req?.body?.clientSecret, req?.body?.redirectUris,
                                        req?.body?.scope, req?.body?.public);
        debug(`Sending client: ${JSON.stringify(client)}`);

        if (client) {
            client.clientSecret = "";
            res.status(200).send(client);
        } else {
            res.status(500).send("Internal error.");
        }
    }
}
export const clientController = new ClientController();