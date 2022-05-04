import { Model, model } from "mongoose";
import { settingsSchema } from "./SettingsSchema";
import ISettingsDocument from "../interfaces/ISettingsDocument";

export const settingsModel: Model<ISettingsDocument> = model<ISettingsDocument>("SettingsModel", settingsSchema);
export default settingsModel;
