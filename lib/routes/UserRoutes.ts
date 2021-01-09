import { Request, Response } from "express";
import * as Debug from "debug";
import { IApplication } from "../app";
const debug = Debug("AuthServer:UserRoutes:");
import Db from "../db/db";
import { compare } from "bcryptjs";

export class UserRoutes {

    public routes(app: IApplication): void {
        let db: Db = app.Db;

        app.post("/users/create", async (req: Request, res: Response) => {
            debug(`Adding User: ${JSON.stringify(req.body)}`);
            let user = await db.addUser(req?.body?.name, req?.body?.email, req?.body?.password, req?.body?.tokens);
            debug(`Sending user: ${JSON.stringify(user)}`);
            res.status(200).send(user);
        });

        app.post("/users/authenticate", async (req: Request, res: Response) => {
            debug (`Login User: ${JSON.stringify(req.body)}`);
            let user = await db.getUser(req?.body?.email);
            let validPassword = undefined;

            if (req?.body?.password && user?.password)
                validPassword = await compare(req?.body?.password, user?.password);

            if (!validPassword) {
                res.status(401).send("Wrong credentials supplied.");
                return;
            }
            debug(`Sending user: ${JSON.stringify(user)}`);
            res.status(200).send(user);
        });
    }
}