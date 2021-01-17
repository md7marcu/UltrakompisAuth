import IAccessToken from "./IAccessToken";
import IIdToken  from "./IIdToken";
import IRefreshToken from "./IRefreshToken";

export default interface IUser {
    userId?: string;
    password: string;
    email: string;
    name: string;
    idTokens?: IIdToken[];
    accessTokens?: IAccessToken[];
    refreshTokens?: IRefreshToken[];
    enabled?: boolean;
    code?: string;
    nonce?: string;
    claims?: string[];
    lastAuthenticated?: string;
}