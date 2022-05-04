import { NextFunction, Request, Response } from "express";
import { config } from "node-config-ts";
import * as Debug from "debug";
import { asyncHandler } from "../middleware/AsyncHandler";
const debug = Debug("AuthServer:ViewRoutes:");

export class ViewRoutes {
    private db;

    public routes(app): void {
        this.db = app.Db;

        app.get("/", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            res.render("index",
                {
                    title: "Authorization Server",
                    endpoints: {
                        authorizationEndpoint: config.settings.authorizationEndpoint,
                        accessTokenEndpoint: config.settings.accessTokenEndpoint,
                        aliveEndpoint: config.settings.aliveEndpoint,
                    },
                });
            next();
        }));

        app.get("/alive", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            res.send("Success!");
            next();
        }));

        app.get("/settings", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            let settingsTitle = "Settings for Authorization Server";
            let settings = config.settings;
            res.render("settings", { title: settingsTitle, clients: settings.clients, users: settings.users, settings: settings});
            next();
        }));

        app.post("/settings", asyncHandler((req: Request, res: Response, next: NextFunction) => {
            console.log(`request: ${JSON.stringify(req?.body)}`);
            next();
        }));
    }
}