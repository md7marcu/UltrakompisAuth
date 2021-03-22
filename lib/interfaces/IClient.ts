export default interface IClient {
    clientId: string;
    clientSecret?: string;
    redirectUris?: string[];
    scopes: string[];
    public?: boolean;
    enabled: boolean;
}