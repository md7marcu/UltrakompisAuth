import { Document } from "mongoose";
import IUser from "../interfaces/IUser";

export default interface IUserDocument extends Document, IUser { }