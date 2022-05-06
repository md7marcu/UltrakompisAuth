import * as fs from "fs";
import { config } from "node-config-ts";

export const setHttpsOptions = (lapp) => {
    lapp.httpsOptions = {
        key: fs.readFileSync("./" + config.settings.appKey),
        cert: fs.readFileSync("./" + config.settings.appCert),
    };
};
export default setHttpsOptions;