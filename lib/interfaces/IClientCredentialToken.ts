/* eslint-disable semi */
/* eslint-disable @typescript-eslint/naming-convention */
export default interface IClientCredentialToken {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    scope: string[];
};