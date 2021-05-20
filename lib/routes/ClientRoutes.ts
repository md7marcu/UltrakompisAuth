import { Request, Response } from "express";
import { IApplication } from "../app";
import Db from "../db/db";
import { clientController } from "../controllers/ClientController";

export class ClientRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.post("/client/create", async (req: Request, res: Response) => {
            clientController.addClient(req, res, db);
        });
    }
}