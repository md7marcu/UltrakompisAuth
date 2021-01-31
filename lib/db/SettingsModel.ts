import { Model, model } from "mongoose";
import { SettingsSchema } from "./SettingsSchema";
import ISettingsDocument from "../interfaces/ISettingsDocument";

export const SettingsModel: Model<ISettingsDocument> = model<ISettingsDocument>("SettingsModel", SettingsSchema);
export default SettingsModel;
