import { NextFunction, Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ServerController:");
import Db from "../db/db";
import { config } from "node-config-ts";

export class ServerController {

    public async wellKnown(req: Request, res: Response, next: NextFunction, database: Db) {
        debug(`Sending well-known`);
        let wellKnownBase = config.wellKnown;
        wellKnownBase.issuer = "";
        wellKnownBase.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownBase.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownBase.userinfo_endpoint = "";
        wellKnownBase.revocation_endpoint = "";

        res.status(200).send(wellKnownBase);
    }
}
export const serverController = new ServerController();