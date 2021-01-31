import { Model, model } from "mongoose";
import { ClientSchema } from "./ClientSchema";
import IClientDocument from "../interfaces/IClientDocument";

export const ClientModel: Model<IClientDocument> = model<IClientDocument>("ClientModel", ClientSchema);
export default ClientModel;
