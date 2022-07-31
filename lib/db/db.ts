import { findIndex, find, remove } from "lodash";
import { Guid } from "guid-typescript";
import { config } from "node-config-ts";
import IClient from "interfaces/IClient";
import IUser from "interfaces/IUser";
import ISettings from "interfaces/ISettings";
import { hash } from "bcryptjs";
import MongoDb from "./MongoDb";
import { decode } from "jsonwebtoken";
import IRefreshToken from "interfaces/IRefreshToken";
import * as Debug from "debug";
const debug = Debug("AuthServer:db");
debug.log = console.log.bind(console);

export default class Db {
    private clients = config.settings.clients;
    private requests = [];
    private authorizationCodes = [];
    private accessTokens = [];
    private refreshTokens = [];
    private idTokens = [];
    private users: [IUser] = config.settings.users;
    private useMongo: boolean = config.settings.useMongo;
    private maxDate = new Date(8640000000000000);

    /* --------------------------------------------- AUTHORIZATION CODE --------------------------------------------- */

    // In memory only - Authorization code is valid for one try - no need to save it on a user
    public getAuthorizationCode(codeId: string) {
        return find(this.authorizationCodes, (c) => c.codeId === codeId)?.object ?? {};
    }

    public saveAuthorizationCode(code: string, object: any) {
        this.authorizationCodes.push({"codeId": code, "object": object});
    }

    public validAuthorizationCode(codeId: string): boolean {
        // eslint-disable-next-line
        return find(this.authorizationCodes, (c) => {return c.codeId === codeId; }) !== undefined;
    }

    public async deleteAuthorizationCode(codeId: string) {
        // Only code value stored on the user record - not the rest of the request
        if (this.useMongo) {
            await new MongoDb().removeAuthorizationCodeFromUser(codeId);
        } else {
            remove(this.authorizationCodes, (code) => {
                return code.codeId === codeId;
            });
        }
    }

    /* --------------------------------------------- REQUEST --------------------------------------------- */

    public saveRequest(requestId: Guid, query: any) {
        this.requests.push({ "requestId": requestId.toString(), "query": query});
    }

    public getRequest(guid: Guid): any {
        let key = guid?.toString() ?? "";

        // eslint-disable-next-line
        return find(this.requests, (r) => r.requestId === guid?.toString())?.query ?? "";
    }

    public deleteRequest(guid: Guid) {
        let stringGuid = guid?.toString() ?? "";

        remove(this.requests, (request) => {
            return request.requestId === stringGuid;
        });
    }

    /* --------------------------------------------- CLIENT --------------------------------------------- */

    // Return client information for given ClientId if available, else undefined
    public async getClient(clientId: string): Promise<IClient> {
        if (this.useMongo) {
            return await new MongoDb().getClient(clientId);
        } else {
            return find(this.clients, (c) => {
                return c.clientId === clientId;
            });
        }
    }

    public async addClient(clientId: string, clientSecret: string, redirectUris: string[], scope: string[],
        publicClient: boolean): Promise<IClient> {
        let client: IClient;

        if (this.useMongo) {
            try {
                client = await new MongoDb().addClient(clientId, clientSecret, redirectUris, scope, publicClient);
            } catch (err) {
                throw err;
            }
        } else {
            client = {
                clientId: clientId,
                clientSecret: clientSecret,
                redirectUris: redirectUris,
                scope: scope,
                public: publicClient,
                enabled: true,
            };
            this.clients.push(client);
        }

        return client;
    }

    public async saveClientRefreshToken(refreshToken: string, clientId: string) {
        if (this.useMongo) {
            await new MongoDb().saveClientRefreshToken(clientId, refreshToken);
        } else {
            let clientIndex = findIndex(this.clients, (element) => {
                return element.clientId === clientId;
            } );

            if (clientIndex >= 0) {
                if (this.clients[clientIndex].refreshTokens){
                    this.clients[clientIndex].refreshTokens.push(refreshToken);
                } else {
                    this.clients[clientIndex].refreshTokens = [refreshToken];
                }
            }
        }
    }

    public async saveClientAccessToken(accessToken: string, clientId: string) {
        if (this.useMongo) {
            let decodedToken = (decode(accessToken) as any);
            await new MongoDb().saveClientAccessToken(clientId, accessToken, decodedToken);
        } else {
            let clientIndex = findIndex(this.clients, (element) => {
                return element.clientId === clientId;
            } );

            if (clientIndex >= 0) {
                if (this.clients[clientIndex].accessTokens) {
                    this.clients[clientIndex].accessTokens.push(accessToken);
                }else {
                    this.clients[clientIndex].accessTokens = [accessToken];
                }
            }
        }
    }

    /* --------------------------------------------- USER --------------------------------------------- */
    public async saveAccessTokenToUser(email: string, accessToken: string) {
        if (this.useMongo) {
            let decodedToken = config.settings.opaqueAccessToken ? undefined : (decode(accessToken) as any);
            await new MongoDb().saveAccessTokenToUser(email, accessToken, decodedToken);
        }
        this.accessTokens.push({"accessToken": accessToken, "email": email});
    }

    public saveAccessToken(accessToken: string, clientId: string) {
        this.accessTokens.push({"accessToken": accessToken, "clientId": clientId});
    }

    public saveRefreshToken(refreshToken: string, clientId: string, scope: string[], email: string) {
        this.refreshTokens.push({"refreshToken": refreshToken, "clientId": clientId, "scope": scope, "email": email});
    }

    public async saveRefreshTokenToUser(email: string, refreshToken: string, clientId: string, scope: string[]) {
        if (this.useMongo) {
            await new MongoDb().saveRefreshTokenToUser(email, refreshToken, Date.now() / 1000 - 200, this.maxDate.getTime(), clientId, scope);
        } else {
            this.refreshTokens.push({"refreshToken": refreshToken, "clientId": clientId, "scope": scope, "email": email});
        }
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

    public async saveIdTokenToUser(email: string, idToken: string)  {
        if (this.useMongo) {
            let decodedToken = (decode(idToken) as any);
            await new MongoDb().saveIdTokenToUser(email, idToken, decodedToken);
        } else {
            this.idTokens.push({idToken: idToken, email: email});
        }
    }

    public async updateUser(userId: string, sinceEpoch: number, code: string) {
        let user: IUser;

        if (this.useMongo) {
            await new MongoDb().updateUser(userId, sinceEpoch, code);
        } else {
            let index = this.users.findIndex(u => u.name === userId);
            this.users[index].lastAuthenticated = sinceEpoch.toString();
            this.users[index].code = code;
        }
    }

    public async addUserObject(user: IUser): Promise<IUser> {
        return await this.addUser(user.name, user.email, user.password, user.claims);
    }

    public async addUser(name: string, email: string, password: string, claims: string[]): Promise<IUser> {
        let user: IUser;

        if (this.useMongo) {
            user = await new MongoDb().addUser(name, email, password, claims);
        } else {
            let hashedPassword = await hash(password, 10);
            user = {
                userId: Guid.create().toString(),
                name: name,
                email: email,
                password: hashedPassword,
                claims: claims,
                enabled: false,
                activationCode: Guid.create().toString(),
            };
            this.users.push(user);
        }

        return user;
    }

    public async activateUser(email: string, activationCode: string): Promise<boolean> {
        if (this.useMongo) {
            let mongo = new MongoDb();
            let user = await mongo.getUserByEmail(email, false);

            if (user?.activationCode === activationCode) {
                await mongo.activateUser(email);

                return true;
            }
            return false;
        } else {
            let user = find(this.users, (u) => u.email === email && u.activationCode === activationCode);
            user.enabled = true;
            user.activationCode = undefined;

            return user !== undefined;
        }
    }

    public async getUser(userId: string): Promise<IUser> {
        if (this.useMongo) {
            return await new MongoDb().getUser(userId);
        } else {
            return find(this.users, (u) => u.userId === userId);
        }
    }

    public async getUserByEmail(email: string): Promise<IUser> {
        if (this.useMongo) {
            return await new MongoDb().getUserByEmail(email);
        } else {
            return find(this.users, (u) => u.email === email);
        }
    }

    public async getUserByAccessToken(token: string): Promise<IUser> {
        if (this.useMongo) {
            return await new MongoDb().getUserByAccessToken(token);
        } else {
            let accessToken = find(this.accessTokens, t => t.accessToken === token);
            return find(this.users, (u) => u.email === accessToken.email);
        }
    }
    /* --------------------------------------------- SETTINGS --------------------------------------------- */
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
