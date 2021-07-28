import { sign } from "jsonwebtoken";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { config } from "node-config-ts";

export default function signToken(options: IVerifyOptions, key: Buffer): string {
        return sign(options, key, { algorithm: config.settings.algorithm });
}
