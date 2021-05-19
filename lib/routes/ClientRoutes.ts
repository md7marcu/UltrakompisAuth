import { Request, Response } from "express";
import * as Debug from "debug";
import { IApplication } from "../app";
const debug = Debug("AuthServer:ClientRoutes:");
import Db from "../db/db";

export class ClientRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.post("/client/create", async (req: Request, res: Response) => {
            debug(`Adding Client: ${JSON.stringify(req.body)}`);
            let client = await db.addClient(req?.body?.clientId, req?.body?.clientSecret, req?.body?.redirectUris,
                                          req?.body?.scope, req?.body?.public);
            debug(`Sending client: ${JSON.stringify(client)}`);

            if (client) {
                client.clientSecret = "";
                res.status(200).send(client);
            } else {
                res.status(500).send("Internal error.");
            }
        });
    }
}