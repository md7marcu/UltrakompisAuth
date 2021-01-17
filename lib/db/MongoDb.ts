import UserModel from "./UserModel";
import IUser from "../interfaces/IUser";
import SettingsModel from "./SettingsModel";
import ISettings from "../interfaces/ISettings";
import * as Debug from "debug";
import { config } from "node-config-ts";
import IAccessToken from "interfaces/IAccessToken";
import IIdToken from "interfaces/IIdToken";
import IRefreshToken from "interfaces/IRefreshToken";

const debug = Debug("AuthServer:MongoDB");
debug.log = console.log.bind(console);

export default class MongoDb {
    public async removeAuthorizationCodeFromUser(email: string) {
        return await UserModel.findOneAndUpdate({email: email}, { code: ""})
        .catch((error) => {
            debug(`Failed to update user ${email} to remove authorization code. Error: ${JSON.stringify(error)}`);
            return undefined;
        });
    }

    public async updateUser(email: string, sinceEpoch: number, code: string) {
        return await UserModel.findOneAndUpdate({email: email}, { lastAuthenticated: sinceEpoch.toString(), code: code })
        .catch((error) => {
            debug(`Failed to update user ${email} with code ${code}. Error: ${JSON.stringify(error)}`);
            return undefined;
        });
    }

    public async addUser(name: string, email: string, password: string, claims: string[]): Promise<IUser> {
        return await new UserModel(
            {
                name: name,
                email: email,
                password:
                password,
                claims: claims,
                enabled: false,
            }).save()
                .catch((error) => {
                    debug(`Failed to add user with email ${email}. err: ${JSON.stringify(error)}`);
                    return undefined;
                });
    }

    public async getUser(email: string): Promise<IUser> {
        return await UserModel.findOne({email: email}).lean();
    }

    public async saveAccessTokenToUser(email: string, accessToken: string, decodedToken: any) {
        let token: IAccessToken = {token: accessToken, created: decodedToken?.iat, expires: decodedToken?.exp};

        await UserModel.findOneAndUpdate({email: email},
                {$push: { accessTokens: { token: accessToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredAccessTokens) {
            await UserModel.findOneAndUpdate({email: email},
                {$pull: { accessTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveIdTokenToUser(email: string, idToken: string, decodedToken: any) {
        let token: IIdToken = {token: idToken, created: decodedToken?.iat, expires: decodedToken?.exp};

        await UserModel.findOneAndUpdate({email: email},
                {$push: { idTokens: { token: idToken, created: decodedToken.iat, expires: decodedToken.exp}}});

        if (config.settings.removeExpiredIdTokens) {
            await UserModel.findOneAndUpdate({email: email},
                {$pull: { idTokens: { expires: { $lt: (Date.now() / 1000)}}}});
        }
    }

    public async saveRefreshTokenToUser(email: string, refreshToken: string, iat: number, exp: number,
        clientId: string, scopes: string[]) {

        await UserModel.findOneAndUpdate({email: email},
                {$push: { refreshTokens: { token: refreshToken, created: iat, expires: exp, clientId: clientId,
                    scopes: scopes, userId: email}}});

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
            })
            .catch((error) => {
                debug(`Failed to upsert the settings ${JSON.stringify(localSettings)}. err ${JSON.stringify(error)}`);
                return undefined;
            });
    }
}