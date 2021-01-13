import { find, remove } from "lodash";
import { Guid } from "guid-typescript";
import { config } from "node-config-ts";
import IClient from "interfaces/IClient";
import IUser from "interfaces/IUser";
import ISettings from "interfaces/ISettings";
import getRandomString from "../helpers/GetRandomString";
import { hash } from "bcryptjs";
import MongoDb from "./MongoDb";

export default class Db {
    private clients = config.settings.clients;
    private requests = [];
    private authorizationCodes = [];
    private accessTokens = [];
    private refreshTokens = [];
    private users: [IUser] = config.settings.users;
    private useMongo: boolean = config.settings.useMongo;
    private isTest: boolean = process.env.NODE_ENV === "test";

    // Return client information for given ClientId if available, else undefined
    public getClient(clientId: string): IClient {
        return find(this.clients, (c) => { return c.clientId === clientId; });
    }

    public saveRequest(requestId: Guid, query: any) {
        this.requests.push({ "requestId": requestId.toString(), "query": query});
    }

    public getRequest(guid: Guid): any {
        let key = guid?.toString() ?? "";

        // tslint:disable-next-line:whitespace
        return find(this.requests, (r) => r.requestId === guid?.toString())?.query ?? "";
    }

    public deleteRequest(guid: Guid) {
        let stringGuid = guid?.toString() ?? "";

        remove(this.requests, (request) => {
            return request.requestId === stringGuid;
        });
    }

    public getAuthorizationCode(codeId: string) {
        return find(this.authorizationCodes, (c) => c.codeId === codeId)?.object ?? {};
    }

    public saveAuthorizationCode(code: string, object: any) {
        this.authorizationCodes.push({"codeId": code, "object": object});
    }

    public deleteAuthorizationCode(codeId: string) {
        remove(this.authorizationCodes, (code) => {
            return code.codeId === codeId;
        });
    }

    public validAuthorizationCode(codeId: string): boolean {
        // tslint:disable-next-line:whitespace
        return find(this.authorizationCodes, (c) => {return c.codeId === codeId; }) !== undefined;
    }

    public saveAccessToken(accessToken: string, clientId: string) {
        this.accessTokens.push({"accessToken": accessToken, "clientId": clientId});
    }

    public validAccessToken(accessToken: string): boolean {
        // tslint:disable-next-line:whitespace
        return find(this.accessTokens, (t) => t.accessToken === accessToken) !== undefined;
    }

    public getAccessToken(accessToken: string) {
        return find(this.accessTokens, (t) => t.accessToken === accessToken);
    }

    public saveRefreshToken(refreshToken: string, clientId: string, scopes: string[]) {
        this.refreshTokens.push({"refreshToken": refreshToken, "clientId": clientId, "scopes": scopes});
    }

    public validRefreshToken(refreshToken: string): boolean {
        // tslint:disable-next-line:whitespace
        return find(this.refreshTokens, (r) => r.refreshToken === refreshToken) !== undefined;
    }

    public getRefreshToken(refreshToken: string) {
        return find(this.refreshTokens, (r) => r.refreshToken === refreshToken);
    }

    public getUserFromCode(code: string): IUser {
        return find(this.users, (r) => r.code === code);
    }

    public updateUser(name: string, sinceEpoch: number, code: string) {
        let index = this.users.findIndex(u => u.name === name);
        this.users[index].lastAuthenticated = sinceEpoch.toString();
        this.users[index].code = code;
    }

    public async addUser(name: string, email: string, password: string, tokens: string[]): Promise<IUser> {
        let hashedPassword = await hash(password, 8);
        let user: IUser;

        if (!this.isTest && this.useMongo) {
            user = await new MongoDb().addUser(name, email, hashedPassword, tokens);
        } else {
            user = {
                userId: getRandomString(8),
                name: name,
                email: email,
                password: hashedPassword,
                tokens: tokens,
                enabled: true,
            };
            console.log(`users: ${JSON.stringify(this.users)}`);
            this.users.push(user);
            console.log(`users after push: ${JSON.stringify(this.users)}`);
        }

        return user;
    }

    public async getUser(email: string): Promise<IUser> {
        if (!this.isTest && this.useMongo) {
            return await new MongoDb().getUser(email);
        } else {
            return find(this.users, (u) => u.email === email);
        }
    }

    public async getSettings(): Promise<ISettings> {
        if (!this.isTest && this.useMongo) {
            return await new MongoDb().getSettings();
        } else {
            return config.settings;
        }
    }

    public async upsertSettings(settings: ISettings): Promise<ISettings> {
        if (!this.isTest && this.useMongo) {
            return await new MongoDb().upsertSettings(settings);
        } else {
            return config.settings;
        }
    }
}
