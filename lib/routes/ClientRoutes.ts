import { NextFunction, Request, Response } from "express";
import { IApplication } from "../app";
import Db from "../db/db";
import { clientController } from "../controllers/ClientController";
import { asyncHandler } from "../middleware/AsyncHandler";

export class ClientRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.post("/client/create", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            clientController.addClient(req, res, next, db);
        }));
    }
}