import { NextFunction, Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ClientController:");
import Db from "../db/db";
import { compareSync } from "bcryptjs";
import { ErrorResponse } from "../helpers/ErrorResponse";

export class UserController {

    public async addUser(req: Request, res: Response, next: NextFunction, database: Db) {
        debug(`Adding User: ${JSON.stringify(req.body)}`);
        let user;
        try {
            user = await database.addUser(req?.body?.name, req?.body?.email, req?.body?.password, req?.body?.claims);
        } catch (err) {
            next(err);
        }
        debug(`Sending user: ${JSON.stringify(user)}`);
        res.status(200).send(user);
    }

    public async authenticateUser(req: Request, res: Response, next: NextFunction, database: Db) {
        debug (`Login User: ${JSON.stringify(req.body)}`);
        try {
            let user = await database.getUserByEmail(req?.body?.email);
            let validPassword = undefined;

            if (req?.body?.password && user?.password)
                validPassword = compareSync(req?.body?.password, user?.password);

            if (!validPassword) {
                next(new ErrorResponse("Wrong credentials supplied.", 401));
                return;
            }
            debug(`Sending user: ${JSON.stringify(user)}`);
            res.status(200).send(user);
        } catch (error) {
            next(error);
        }
    }
}
export const userController = new UserController();