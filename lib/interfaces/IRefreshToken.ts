export default interface IRefreshToken {
    token: string;
    created: number;
    expires: number;
    clientId: string;
    scopes: string[];
    userId: string;
}
