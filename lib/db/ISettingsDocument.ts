import { Document } from "mongoose";
import ISettings from "../interfaces/ISettings";

export default interface ISettingsDocument extends Document, ISettings { }