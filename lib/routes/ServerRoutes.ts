import { NextFunction, Request, Response } from "express";
import { IApplication } from "../app";
import Db from "../db/db";
import { serverController } from "../controllers/ServerController";
import { asyncHandler } from "../middleware/AsyncHandler";

export class ServerRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.get("/.well-known/openid-configuration", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            serverController.wellKnown(req, res, next, db);
        }));
    }
}