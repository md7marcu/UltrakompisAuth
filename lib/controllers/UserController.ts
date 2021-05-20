import { Request, Response } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:ClientRoutes:");
import Db from "../db/db";
import { compareSync } from "bcryptjs";

export class UserController {

    public async addUser(req: Request, res: Response, database: Db) {
        debug(`Adding User: ${JSON.stringify(req.body)}`);
        let user = await database.addUser(req?.body?.name, req?.body?.email, req?.body?.password, req?.body?.claims);
        debug(`Sending user: ${JSON.stringify(user)}`);

        if (user) {
            res.status(200).send(user);
        } else {
            res.status(500).send("Internal error.");
        }
    }

    public async authenticateUser(req: Request, res: Response, database: Db) {
        debug (`Login User: ${JSON.stringify(req.body)}`);
        let user = await database.getUser(req?.body?.email);

        let validPassword = undefined;

        if (req?.body?.password && user?.password)
            validPassword = compareSync(req?.body?.password, user?.password);

        if (!validPassword) {
            res.status(401).send("Wrong credentials supplied.");
            return;
        }
        debug(`Sending user: ${JSON.stringify(user)}`);
        res.status(200).send(user);
    }
}
export const userController = new UserController();