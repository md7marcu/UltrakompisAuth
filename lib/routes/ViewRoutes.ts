import { Request, Response } from "express";
import { config } from "node-config-ts";
import * as Debug from "debug";
const debug = Debug("AuthServer:ViewRoutes:");

export class ViewRoutes {
    private db;

    public routes(app): void {
        this.db = app.Db;

        app.get("/", async(req: Request, res: Response) => {
            res.render("index",
            {
                title: "Authorization Server",
                endpoints: {
                    authorizationEndpoint: config.settings.authorizationEndpoint,
                    accessTokenEndpoint: config.settings.accessTokenEndpoint,
                    aliveEndpoint: config.settings.aliveEndpoint,
                },
            });
        });

        app.get("/alive", async(req: Request, res: Response) => {
            res.send("Success!");
        });

        app.get("/settings", async(req: Request, res: Response) => {
            let settingsTitle = "Settings for Authorization Server";
            let settings = config.settings;
            res.render("settings", { title: settingsTitle, clients: settings.clients, users: settings.users, settings: settings});
        });

        app.post("/settings", async(req: Request, res: Response) => {
            console.log(`request: ${JSON.stringify(req?.body)}`);
        });
    }
}