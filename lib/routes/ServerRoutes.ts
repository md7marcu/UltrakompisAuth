import { NextFunction, Request, Response } from "express";
import { IApplication } from "../app";
import Db from "../db/db";
import { serverController } from "../controllers/ServerController";
import { asyncHandler } from "../middleware/AsyncHandler";
import verifyToken from "../helpers/VerifyToken";
import { decode } from "jsonwebtoken";
import { IUserRequest } from "../interfaces/IRequest";

export class ServerRoutes {
    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.get("/.well-known/openid-configuration", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            serverController.wellKnown(req, res, next, db);
        }));

        app.get("/oauth2/certs", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            serverController.certs(req, res, next, app.httpsOptions.cert);
        }));

        app.get("/userinfo", this.verifyUser(app), asyncHandler((req: IUserRequest, res: Response, next: NextFunction) => {
            // req should contain the userid from verifyuser
            if (!req.userId) {
                res.status(401).send("Invalid token.");

                return;
            }
            serverController.userInfo(req, res, next, db);
        }));

        app.post("/userinfo", this.verifyUser(app), asyncHandler((req: IUserRequest, res: Response, next: NextFunction) => {
            // req should contain the userid from verifyuser
            if (!req.userId) {
                res.status(401).send("Invalid token.");

                return;
            }
            serverController.userInfo(req, res, next, db);
        }));
    }

    private verifyUser = (app) => {
        return async(req: IUserRequest, res: Response, next: NextFunction): Promise<any> => {
            try {
                if (verifyToken(req?.headers?.authorization, app?.httpsOptions?.cert)) {
                    let decodedToken = decode(req.headers.authorization);
                    req.userId = decodedToken.sub;
                }
            } catch (error) {
                next(error);
            }
            next();
        };
    }
}