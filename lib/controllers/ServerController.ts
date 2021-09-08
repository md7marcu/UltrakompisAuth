import { NextFunction, Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ServerController:");
import Db from "../db/db";
import { config } from "node-config-ts";
import createJwk from "../helpers/Jwks";
import { IUserRequest } from "../interfaces/IRequest";
import IUser from "interfaces/IUser";

export class ServerController {

    public async wellKnownOpenIdConfiguration(req: Request, res: Response, next: NextFunction, database: Db) {
        debug(`Sending well-known openid configuration`);
        let wellKnownBase = config.wellKnown;
        wellKnownBase.issuer = config.settings.issuer;
        wellKnownBase.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownBase.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownBase.jwks_uri = config.settings.jwksEndpoint;
        wellKnownBase.userinfo_endpoint = config.settings.userinfoEndpoint;
        wellKnownBase.revocation_endpoint = "";

        res.status(200).send(wellKnownBase);
    }

    public async wellKnownServer(req: Request, res: Response, next: NextFunction, database: Db) {
        debug(`Sending well-known server`);
        let wellKnownBase = config.wellKnown;
        wellKnownBase.issuer = config.settings.issuer;
        wellKnownBase.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownBase.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownBase.scopes_supported = config.settings.scopes_supported;
        wellKnownBase.response_types_supported = config.settings.response_types_supported;
        wellKnownBase.jwks_uri = config.settings.jwksEndpoint;
        wellKnownBase.userinfo_endpoint = config.settings.userinfoEndpoint;
        wellKnownBase.revocation_endpoint = "";
        wellKnownBase.token_endpoint_auth_signing_alg_values_supported = config.settings.token_endpoint_auth_signing_alg_values_supported;
        wellKnownBase.grant_types_supported = config.settings.grant_types_supported;

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

    private getUserInfo(user: IUser): any {
        return {
            "sub": user.userId,
            "name": user.name,
            "email": user.email,
        };
    }
}
export const serverController = new ServerController();