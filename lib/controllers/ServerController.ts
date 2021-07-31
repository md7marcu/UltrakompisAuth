import { NextFunction, Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ServerController:");
import Db from "../db/db";
import { config } from "node-config-ts";
import createJwk from "../helpers/Jwks";
import { IUserRequest } from "../interfaces/IRequest";
import IUser from "interfaces/IUser";

export class ServerController {

    public async wellKnown(req: Request, res: Response, next: NextFunction, database: Db) {
        debug(`Sending well-known`);
        let wellKnownBase = config.wellKnown;
        wellKnownBase.issuer = config.settings.issuer;
        wellKnownBase.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownBase.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownBase.jwks_uri = config.settings.jwksEndpoint;
        wellKnownBase.userinfo_endpoint = "";
        wellKnownBase.revocation_endpoint = "";

        res.status(200).send(wellKnownBase);
    }

    public async certs(req: Request, res: Response, next: NextFunction, cert: Buffer) {
        debug(`Sending certs`);
        let jwk = (await createJwk(cert)).toJSON();
        jwk.use = config.settings.jwkUse;
        jwk.alg = config.settings.jwkAlgorithm;

        res.status(200).send({"keys": [jwk]});
    }

    public async userInfo(req: IUserRequest, res: Response, next: NextFunction, database: Db) {
        debug(`Sending User Info`);
        let user = await database.getUser(req.userId);

        if (!user) {
            res.status(401).send("Unknown user.");

            return;
        }
        res.status(200).send(this.getUserInfo(user));
    }

    private getUserInfo(user: IUser): string {
        return JSON.stringify({
            "sub": user.userId,
            "name": user.name,
            "email": user.email,
        });
    }
}
export const serverController = new ServerController();