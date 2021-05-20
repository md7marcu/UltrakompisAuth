import { Request, Response, NextFunction } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:AuthRoutes:");
import { IRequest } from "../interfaces/IRequest";
import { compare } from "bcryptjs";
import { authController } from "../controllers/AuthController";

export class AuthRoutes {
    private db;

    public routes(app): void {
        this.db = app.Db;

        app.get("/", async(req: IRequest, res: Response) => {
            authController.root(req, res);
        });

        app.get("/alive", async(req: IRequest, res: Response) => {
            authController.alive(req, res);
        });

        app.get("/authorize", async(req: IRequest, res: Response) => {
            authController.authorize(req, res, this.db);
        });

        app.post("/allowRequest", this.authenticateUser, async(req: Request, res: Response) => {
            authController.allowRequest(req, res, this.db);
        });

        app.post("/token", async(req: Request, res: Response) => {
            authController.token(req, res, app);
        });
    }

    private authenticateUser = async(req: IRequest, res: Response, next: NextFunction): Promise<any> => {
        let username = req?.body?.username;
        let user = await this.db.getUser(username);
        let password = req?.body?.password ? req?.body?.password : "";

        if (!user || password === "" || !user.enabled) {
            req.body.authenticated = false;
        } else {
            req.body.authenticated = await compare(password, user?.password);
        }
        next();
    }
}