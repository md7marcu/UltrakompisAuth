import { NextFunction, Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ClientController");
import Db from "../db/db";
import IClient from "interfaces/IClient";

export class ClientController {

    public async addClient(req: Request, res: Response, next: NextFunction, database: Db ) {
        debug(`Adding Client: ${JSON.stringify(req.body)}`);
        let client: IClient = undefined;

        try {
            client = await database.addClient(req?.body?.clientId, req?.body?.clientSecret, req?.body?.redirectUris,
                req?.body?.scope, req?.body?.public);
        } catch (err) {
            next(err);
        }

        if (client) {
            client.clientSecret = "";
            debug(`Sending client: ${JSON.stringify(client)}`);
            res.status(200).send(client);
        }
    }
}
export const clientController = new ClientController();