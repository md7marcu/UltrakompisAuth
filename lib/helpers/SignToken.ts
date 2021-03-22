import * as Fs from "fs";
import { sign } from "jsonwebtoken";
import * as path from "path";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { config } from "node-config-ts";

export default function signToken(options: IVerifyOptions): string {
        return sign(options, Fs.readFileSync(path.join(__dirname, "../../config/key.pem")), { algorithm: config.settings.algorithm });
}
