export default interface IUser {
    userId?: string;
    password: string;
    email: string;
    name: string;
    tokens?: string[];
    enabled?: boolean;
    code?: string;
    nonce?: string;
    lastAuthenticated?: string;
}