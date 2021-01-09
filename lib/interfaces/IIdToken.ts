export default interface IIdToken {
    iss: string;
    sub: string;
    aud: string;
    exp: number;
    iat: number;
    auth_time: string;
    nonce: string;
}