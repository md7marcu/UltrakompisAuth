import { Request, Response, NextFunction } from "express";
import * as Debug from "debug";
const debug = Debug("AuthServer:AuthRoutes:");
import { IRequest } from "../interfaces/IRequest";
import { compare } from "bcryptjs";
import { authController } from "../controllers/AuthController";
import { asyncHandler } from "../middleware/AsyncHandler";

export class AuthRoutes {
    private db;

    public routes(app): void {
        this.db = app.Db;

        app.get("/", asyncHandler((req: IRequest, res: Response, next: NextFunction) => {
            authController.root(req, res, next);
        }));

        app.get("/alive", asyncHandler((req: IRequest, res: Response, next: NextFunction) => {
            authController.alive(req, res, next);
        }));

        app.get("/authorize", asyncHandler((req: IRequest, res: Response, next: NextFunction) => {
            authController.authorize(req, res, next, this.db);
        }));

        app.post("/allowRequest", this.authenticateUser, asyncHandler((req: Request, res: Response, next: NextFunction) => {
            authController.allowRequest(req, res, next, this.db);
        }));

        app.post("/token", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            authController.token(req, res, next, app);
        }));
    }

    private authenticateUser = async(req: IRequest, res: Response, next: NextFunction): Promise<any> => {
        let username = req?.body?.username;
        let user;

        try {
            user = await this.db.getUserByEmail(username);
        } catch (err) {
            next(err);
        }
        let password = req?.body?.password ?? "";

        if (!user || password === "" || !user.enabled) {
            req.body.authenticated = false;
        } else {
            req.body.authenticated = await compare(password, user?.password);
        }
        next();
    };
}