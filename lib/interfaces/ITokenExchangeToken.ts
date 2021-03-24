export default interface ITokenExchangeToken {
    access_token: string,
    token_type: string,
    expires_in: number,
    scope: string[],
    issued_token_type: string,
}
