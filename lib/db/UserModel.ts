import { Model, model } from "mongoose";
import { UserSchema } from "./UserSchema";
import IUserDocument from "../interfaces/IUserDocument";

export const UserModel: Model<IUserDocument> = model<IUserDocument>("UserModel", UserSchema);
export default UserModel;
