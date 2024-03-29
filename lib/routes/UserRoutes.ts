import { NextFunction, Request, Response } from "express";
import * as Debug from "debug";
import { IApplication } from "../app";
const debug = Debug("AuthServer:UserRoutes:");
import Db from "../db/db";
import {userController} from "../controllers/UserController";
import { asyncHandler } from "../middleware/AsyncHandler";

export class UserRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.db;

        app.post("/users/create", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            userController.addUser(req, res, next, db);
        }));

        app.post("/users/authenticate", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            userController.authenticateUser(req, res, next, db);
        }));

        app.post("/users/activate", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            userController.activateUser(req, res, next, db);
        }));
    }
}