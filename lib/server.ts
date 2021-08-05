// lib/server.ts
import app from "./app";
import * as https from "https";
import * as fs from "fs";
import * as Debug from "debug";
import IHttpsOptions from "./interfaces/IHttpsOptions";
import { config } from "node-config-ts";
const debug = Debug("AuthServer");

const PORT = process.env.PORT;

const httpsOptions: IHttpsOptions = {
    key: fs.readFileSync(config.settings.appKey),
    cert: fs.readFileSync(config.settings.appCert),
};

https.createServer(httpsOptions, app).listen(PORT, () => {
    app.httpsOptions = httpsOptions;
    console.log("Express server listening on port " + PORT);
    debug("Express server listening on port " + PORT);
});
