import UserModel from "./UserModel";
import IUser from "../interfaces/IUser";
import SettingsModel from "./SettingsModel";
import ISettings from "../interfaces/ISettings";
import * as Debug from "debug";
import { config } from "node-config-ts";

const debug = Debug("AuthServer:MongoDB");
debug.log = console.log.bind(console);

export default class MongoDb {

    public async addUser(name: string, email: string, password: string, tokens: string[]): Promise<IUser> {
        let users = await UserModel.find({email: email});

        return await new UserModel(
            {
                name: name,
                email: email,
                password:
                password,
                tokens: tokens,
                enabled: false,
            }).save()
                .catch((error) => {
                    debug(`Failed to add user with email ${email}. err: ${JSON.stringify(error)}`);
                    return undefined;
                });
    }

    public async getUser(email: string): Promise<IUser> {
        return await UserModel.findOne({email: email});
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