import { buildUserAccessToken } from "../../lib/helpers/BuildAccessToken";
import signToken from "../../lib/helpers/SignToken";
import IUser from "../../lib/interfaces/IUser";

export const buildAndSignToken = async (user: IUser, key: Buffer): Promise<string> => {
    let payload = await buildUserAccessToken(undefined, undefined, user);

    return signToken(payload, key);
};