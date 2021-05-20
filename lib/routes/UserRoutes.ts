import { Request, Response } from "express";
import * as Debug from "debug";
import { IApplication } from "../app";
const debug = Debug("AuthServer:UserRoutes:");
import Db from "../db/db";
import {userController} from "../controllers/UserController";

export class UserRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.post("/users/create", async (req: Request, res: Response) => {
            userController.addUser(req, res, db);
        });

        app.post("/users/authenticate", async (req: Request, res: Response) => {
            userController.authenticateUser(req, res, db);
        });
    }
}