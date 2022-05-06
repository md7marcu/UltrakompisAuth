import { Model, model } from "mongoose";
import { userSchema } from "./UserSchema";
import IUserDocument from "../interfaces/IUserDocument";

export const userModel: Model<IUserDocument> = model<IUserDocument>("UserModel", userSchema);
export default userModel;
