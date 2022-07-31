import userModel from "./UserModel";
import IUser from "../interfaces/IUser";
import settingsModel from "./SettingsModel";
import ISettings from "../interfaces/ISettings";
import * as Debug from "debug";
import { config } from "node-config-ts";
import IRefreshToken from "interfaces/IRefreshToken";
import clientModel from "./ClientModel";
import IClient from "interfaces/IClient";
import { Guid } from "guid-typescript";
import { sanitize } from "mongo-sanitize";

const debug = Debug("AuthServer:MongoDB");
debug.log = console.log.bind(console);

export default class MongoDb {
    // --------------------------------------------- USER ---------------------------------------------
    public async removeAuthorizationCodeFromUser(email: string) {
        return await userModel.findOneAndUpdate({email: email}, { code: ""})
            .catch((error) => {
                throw error;
            });
    }

    public async updateUser(email: string, sinceEpoch: number, code: string) {
        return await userModel.findOneAndUpdate({email: email}, { lastAuthenticated: sinceEpoch.toString(), code: code })
            .catch((error) => {
                throw error;
            });
    }

    public async addUser(name: string, email: string, password: string, claims: string[]): Promise<IUser> {
        return await new userModel(
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
        return await userModel.findOne({userId: userId, enabled: true}).lean();
    }

    public async getUserByEmail(email: string): Promise<IUser> {
        return await userModel.findOne({email: email, enabled: true}).lean();
    }

    // TODO: Missing test
    public async activateUser(email: string): Promise<IUser> {
        return await userModel.findOneAndUpdate({email: email}, {enabled: true, activationCode: ""})
            .catch((error) => {
                throw error;
            });
    }

    // TODO: Missing test
    public async getUserByAccessToken(token: string): Promise<IUser> {
        let user = await userModel.findOne({ accessTokens: {$elemMatch: {token: token}}}).lean();

        return user;
    }

    public async saveAccessTokenToUser(email: string, accessToken: string, decodedToken: any) {
        await userModel.findOneAndUpdate({email: email},
            {$push: { accessTokens: { token: accessToken, created: decodedToken?.iat, expires: decodedToken?.exp}}});

        if (config.settings.removeExpiredAccessTokens) {
            await userModel.findOneAndUpdate({email: email},
                {$pull: { accessTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveIdTokenToUser(email: string, idToken: string, decodedToken: any) {
        await userModel.findOneAndUpdate({email: email},
            {$push: { idTokens: { token: idToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredIdTokens) {
            await userModel.findOneAndUpdate({email: email},
                {$pull: { idTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveRefreshTokenToUser(email: string, refreshToken: string, iat: number, exp: number,
        clientId: string, scope: string[]) {

        await userModel.findOneAndUpdate({email: email},
            {$push: { refreshTokens: { token: refreshToken, created: iat, expires: exp, clientId: clientId,
                scope: scope, email: email}}});

        if (config.settings.removeExpiredRefreshTokens) {
            await userModel.findOneAndUpdate({email: email},
                {$pull: { refreshTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async validateRefreshToken(refreshToken: string): Promise<boolean> {
        let user = await userModel.findOne({ refreshTokens: {$elemMatch: {token: refreshToken}}}).lean() ?? undefined;

        return user !== undefined;
    }

    public async getRefreshTokenData(refreshToken: string): Promise<IRefreshToken> {
        let user = await userModel.findOne({ refreshTokens: {$elemMatch: {token: refreshToken}}}).lean();

        return user?.refreshTokens?.find(element => element.token === refreshToken);
    }

    // --------------------------------------------- SETTINGS ---------------------------------------------
    public async getSettings(): Promise<ISettings> {
        let sanitized = sanitize(config.settings.overrideId);
        let localSettings = await settingsModel.findOne({overrideId: sanitized});

        return localSettings ?? config.settings;
    }

    // need to pass in the settings after they've been saved
    public async upsertSettings(settings: ISettings): Promise<ISettings> {
        let sanitized = sanitize(config.settings.overrideId);
        let localSettings = settings ?? config.settings;

        return await settingsModel.findOneAndUpdate({overrideId: sanitized}, localSettings, {
            new: true,
            upsert: true,
        }).catch((error) => {
            throw error;
        });
    }

    // --------------------------------------------- CLIENT ---------------------------------------------
    public async addClient(clientId: string, clientSecret: string, redirectUris: string[], scope: string[],
        publicClient: boolean): Promise<IClient> {

        return await new clientModel(
            {
                clientId: clientId,
                clientSecret: clientSecret,
                redirectUris: redirectUris,
                scope: scope,
                public: publicClient,
                enabled: false,
            }).save().catch((error) => {
            throw error;
        });
    }
    public async getClient(clientId: string): Promise<IClient> {
        return await clientModel.findOne({clientId: clientId, enabled: true}).lean();
    }

    public async validateClientRefreshToken(refreshToken: string): Promise<boolean> {
        let user = await clientModel.findOne({ refreshTokens: refreshToken}).lean() ?? undefined;

        return user !== undefined;
    }

    public async saveClientAccessToken(clientId: string, accessToken: string, decodedToken: any) {
        await clientModel.findOneAndUpdate({clientId: clientId},
            {$push: { accessTokens: { token: accessToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredAccessTokens) {
            await clientModel.findOneAndUpdate({clientId: clientId},
                {$pull: { accessTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveClientRefreshToken(clientId: string, refreshToken: string) {
        await clientModel.findOneAndUpdate({clientId: clientId}, {$push: { refreshToken: refreshToken}});
    }
}