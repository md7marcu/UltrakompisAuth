import UserModel from "./UserModel";
import IUser from "../interfaces/IUser";
import SettingsModel from "./SettingsModel";
import ISettings from "../interfaces/ISettings";
import * as Debug from "debug";
import { config } from "node-config-ts";
import IAccessToken from "interfaces/IAccessToken";
import IIdToken from "interfaces/IIdToken";
import IRefreshToken from "interfaces/IRefreshToken";
import ClientModel from "./ClientModel";
import IClient from "interfaces/IClient";
import { Guid } from "guid-typescript";

const debug = Debug("AuthServer:MongoDB");
debug.log = console.log.bind(console);

export default class MongoDb {
    // --------------------------------------------- USER ---------------------------------------------
    public async removeAuthorizationCodeFromUser(email: string) {
        return await UserModel.findOneAndUpdate({email: email}, { code: ""})
        .catch((error) => { throw error; });
    }

    public async updateUser(email: string, sinceEpoch: number, code: string) {
        return await UserModel.findOneAndUpdate({email: email}, { lastAuthenticated: sinceEpoch.toString(), code: code })
        .catch((error) => { throw error; });
    }

    public async addUser(name: string, email: string, password: string, claims: string[]): Promise<IUser> {
        return await new UserModel(
            {
                userId: Guid.create().toString(),
                name: name,
                email: email,
                password: password,
                claims: claims,
                enabled: false,
            }).save();
    }

    public async getUser(userId: string): Promise<IUser> {
        return await UserModel.findOne({userId: userId, enabled: true}).lean();
    }

    public async getUserByEmail(email: string): Promise<IUser> {
        return await UserModel.findOne({email: email, enabled: true}).lean();
    }

    public async saveAccessTokenToUser(email: string, accessToken: string, decodedToken: any) {
        await UserModel.findOneAndUpdate({email: email},
                {$push: { accessTokens: { token: accessToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredAccessTokens) {
            await UserModel.findOneAndUpdate({email: email},
                {$pull: { accessTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveIdTokenToUser(email: string, idToken: string, decodedToken: any) {
        await UserModel.findOneAndUpdate({email: email},
                {$push: { idTokens: { token: idToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredIdTokens) {
            await UserModel.findOneAndUpdate({email: email},
                {$pull: { idTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveRefreshTokenToUser(email: string, refreshToken: string, iat: number, exp: number,
        clientId: string, scope: string[]) {

        await UserModel.findOneAndUpdate({email: email},
                {$push: { refreshTokens: { token: refreshToken, created: iat, expires: exp, clientId: clientId,
                    scope: scope, email: email}}});

        if (config.settings.removeExpiredRefreshTokens) {
            await UserModel.findOneAndUpdate({email: email},
                {$pull: { refreshTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async validateRefreshToken(refreshToken: string): Promise<boolean> {
        let user = await UserModel.findOne({ refreshTokens: {$elemMatch: {token: refreshToken}}}).lean();

        return user !== null;
    }

    public async getRefreshTokenData(refreshToken: string): Promise<IRefreshToken> {
        let user = await UserModel.findOne({ refreshTokens: {$elemMatch: {token: refreshToken}}}).lean();

        return user?.refreshTokens?.find(element => element.token === refreshToken);
    }

    // --------------------------------------------- SETTINGS ---------------------------------------------
    public async getSettings(): Promise<ISettings> {
        let localSettings = await SettingsModel.findOne({overrideId: config.settings.overrideId});

        if (localSettings === null) {
            return config.settings;
        }
        return localSettings;
    }

    // need to pass in the settings after they've been saved
    public async upsertSettings(settings: ISettings): Promise<ISettings> {
        debug(`upsertSettings: ${JSON.stringify(config.settings)}`);
        let savedSettings = await SettingsModel.findOne({overrideId: config.settings.overrideId});

        let localSettings = settings === undefined ? config.settings : settings;
        console.log(`insert: ${JSON.stringify(settings)}`);

        return await SettingsModel.findOneAndUpdate({overrideId: config.settings.overrideId}, localSettings, {
            new: true,
            upsert: true,
            }).catch((error) => { throw error; });
    }

    // --------------------------------------------- CLIENT ---------------------------------------------
    public async addClient(clientId: string, clientSecret: string, redirectUris: string[], scope: string[],
              publicClient: boolean): Promise<IClient> {

        return await new ClientModel(
            {
                clientId: clientId,
                clientSecret: clientSecret,
                redirectUris: redirectUris,
                scope: scope,
                public: publicClient,
                enabled: false,
            }).save().catch((error) => { throw error; });
    }
    public async getClient(clientId: string): Promise<IClient> {
        return await ClientModel.findOne({clientId: clientId, enabled: true}).lean();
    }

    public async validateClientRefreshToken(refreshToken: string): Promise<boolean> {
        let user = await ClientModel.findOne({ refreshTokens: refreshToken}).lean();

        return user !== null;
    }

    public async saveClientAccessToken(clientId: string, accessToken: string, decodedToken: any) {
        await ClientModel.findOneAndUpdate({clientId: clientId},
                {$push: { accessTokens: { token: accessToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredAccessTokens) {
            await ClientModel.findOneAndUpdate({clientId: clientId},
                {$pull: { accessTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveClientRefreshToken(clientId: string, refreshToken: string) {
        await ClientModel.findOneAndUpdate({clientId: clientId}, {$push: { refreshToken: refreshToken}});
    }
}