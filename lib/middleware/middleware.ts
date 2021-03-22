import { Response, NextFunction } from "express";
import { IRequest } from "../interfaces/IRequest";
import * as Debug from "debug";
const debug = Debug("AuthServer:AuthRoutes:");

export const logger = async(req: IRequest, res: Response, next: NextFunction): Promise<any> => {
    debug(`${req.method} ${req.protocol}://${req.get("host")}${req.originalUrl}`);
    next();
};

// TODO: include and use Morgan - config parameter