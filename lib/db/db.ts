import { find, remove } from "lodash";
import { Guid } from "guid-typescript";
import { config } from "node-config-ts";
import IClient from "interfaces/IClient";
import IUser from "interfaces/IUser";
import ISettings from "interfaces/ISettings";
import getRandomString from "../helpers/GetRandomString";
import { hash } from "bcryptjs";
import MongoDb from "./MongoDb";
import { decode } from "jsonwebtoken";
import IRefreshToken from "interfaces/IRefreshToken";

export default class Db {
    private clients = config.settings.clients;
    private requests = [];
    private authorizationCodes = [];
    private accessTokens = [];
    private refreshTokens = [];
    private idTokens = [];
    private users: [IUser] = config.settings.users;
    private useMongo: boolean = config.settings.useMongo;
    private isTest: boolean = process.env.NODE_ENV === "test";
    private maxDate = new Date(8640000000000000);

    // In memory only - Authorization code is valid for one try - no need to save it on a user
    public getAuthorizationCode(codeId: string) {
        return find(this.authorizationCodes, (c) => c.codeId === codeId)?.object ?? {};
    }

    public saveAuthorizationCode(code: string, object: any) {
        this.authorizationCodes.push({"codeId": code, "object": object});
    }

    public validAuthorizationCode(codeId: string): boolean {
        // tslint:disable-next-line:whitespace
        return find(this.authorizationCodes, (c) => {return c.codeId === codeId; }) !== undefined;
    }

    public async deleteAuthorizationCode(codeId: string) {
        // Only code value stored on the user record - not the rest of the request
        if (this.useMongo) {
            await new MongoDb().removeAuthorizationCodeFromUser(codeId);
        }

        remove(this.authorizationCodes, (code) => {
            return code.codeId === codeId;
        });
    }

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

    public async saveAccessTokenToUser(email: string, accessToken: string) {
        if (this.useMongo) {
            let decodedToken = (decode(accessToken) as any);
            await new MongoDb().saveAccessTokenToUser(email, accessToken, decodedToken);
        }
        this.accessTokens.push({"accessToken": accessToken, "email": email});
    }

    public saveAccessToken(accessToken: string, clientId: string) {
        this.accessTokens.push({"accessToken": accessToken, "clientId": clientId});
    }

    public saveRefreshToken(refreshToken: string, clientId: string, scopes: string[], userid: string) {
        this.refreshTokens.push({"refreshToken": refreshToken, "clientId": clientId, "scopes": scopes, "userid": userid});
    }

    public async saveRefreshTokenToUser(userid: string, refreshToken: string, clientId: string, scopes: string[]) {
        if (this.useMongo) {
            await new MongoDb().saveRefreshTokenToUser(userid, refreshToken, Date.now() / 1000 - 200, this.maxDate.getTime(), clientId, scopes);
        }
        this.refreshTokens.push({"refreshToken": refreshToken, "clientId": clientId, "scopes": scopes, "userid": userid});
    }

    public async validRefreshToken(refreshToken: string): Promise<boolean> {
        if (this.useMongo) {
            return await new MongoDb().validateRefreshToken(refreshToken);
        } else {
            return find(this.refreshTokens, (r) => r.refreshToken === refreshToken) !== undefined;
        }
    }

    public async getRefreshToken(refreshToken: string): Promise<IRefreshToken> {
        if (this.useMongo) {
            return await new MongoDb().getRefreshTokenData(refreshToken);
        } else {
            return find(this.refreshTokens, (r) => r.refreshToken === refreshToken);
        }
    }

    public async saveIdTokenToUser(userid: string, idToken: string)  {
        if (this.useMongo) {
            let decodedToken = (decode(idToken) as any);
            await new MongoDb().saveIdTokenToUser(userid, idToken, decodedToken);
        }
        this.idTokens.push({idToken: idToken, userId: userid});
    }

    public async updateUser(email: string, sinceEpoch: number, code: string) {
        let user: IUser;

        if (this.useMongo) {
            await new MongoDb().updateUser(email, sinceEpoch, code);
        } else {
            let index = this.users.findIndex(u => u.name === email);
            this.users[index].lastAuthenticated = sinceEpoch.toString();
            this.users[index].code = code;
        }
    }

    public async addUserObject(user: IUser): Promise<IUser> {
        return await this.addUser(user.name, user.email, user.password, user.claims);
    }

    public async addUser(name: string, email: string, password: string, claims: string[]): Promise<IUser> {
        let hashedPassword = await hash(password, 8);
        let user: IUser;

        if (this.useMongo) {
            user = await new MongoDb().addUser(name, email, hashedPassword, claims);
        } else {
            user = {
                userId: getRandomString(8),
                name: name,
                email: email,
                password: hashedPassword,
                claims: claims,
                enabled: true,
            };
            this.users.push(user);
        }

        return user;
    }

    public async getUser(email: string): Promise<IUser> {
        if (this.useMongo) {
            return await new MongoDb().getUser(email);
        } else {
            return find(this.users, (u) => u.email === email);
        }
    }

    public async getSettings(): Promise<ISettings> {
        if (this.useMongo) {
            return await new MongoDb().getSettings();
        } else {
            return config.settings;
        }
    }

    public async upsertSettings(settings: ISettings): Promise<ISettings> {
        if (this.useMongo) {
            return await new MongoDb().upsertSettings(settings);
        } else {
            return config.settings;
        }
    }
}
