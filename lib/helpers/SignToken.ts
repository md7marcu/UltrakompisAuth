import * as Fs from "fs";
import { sign } from "jsonwebtoken";
import * as path from "path";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { config } from "node-config-ts";

export default function signToken(options: IVerifyOptions, key:Buffer): string {
        return sign(options, key, { algorithm: config.settings.algorithm });
}
