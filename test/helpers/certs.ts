import * as fs from "fs";

export const setHttpsOptions = (lapp) => {
    lapp.httpsOptions = {
        key: fs.readFileSync("./config/key.pem"),
        cert: fs.readFileSync("./config/cert.pem"),
    };
};
export default setHttpsOptions;