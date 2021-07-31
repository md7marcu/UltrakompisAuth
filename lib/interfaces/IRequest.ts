import { Request } from "express";
export interface IRequest extends Request {
    clientId: string;
}

export interface IUserRequest extends Request {
    userId: string;
}