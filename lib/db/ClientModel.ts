import { Model, model } from "mongoose";
import { clientSchema } from "./ClientSchema";
import IClientDocument from "../interfaces/IClientDocument";

export const clientModel: Model<IClientDocument> = model<IClientDocument>("ClientModel", clientSchema);
export default clientModel;
