export default interface IClient {
    clientId: string;
    clientSecret?: string;
    redirectUris?: string[];
    scope: string[];
    public?: boolean;
    enabled: boolean;
}