export default interface IRefreshToken {
    token: string;
    created: number;
    expires: number;
    clientId: string;
    scope: string[];
    userId: string;
}
