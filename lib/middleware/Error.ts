import Debug from "debug";
import { ErrorResponse } from "../helpers/ErrorResponse";
const debug = Debug("SmurflandiaWebBff:Error:");

export const errorHandler = (err, req, res, next) => {
    let error = { ...err };
    error.message = err.message;

    debug(`err stack: ${err.stack}`);

    // Mongoose bad id
    if (err.name === "CastError") {
        const message = `Resource with id ${err.value} not found.`;
        error = new ErrorResponse(message, 404);
    }

    // Mongoose duplicate key (MongoError)
    if (err.code === 11000) {
        const message = "Duplicate record";
        error = new ErrorResponse(message, 400);
    }

    // Mongoose validation error
    if (err.name === "ValidationError") {
        const message: string = Object.values(error.errors).map(val => (val as any).message).join(",");
        error = new ErrorResponse(message, 400);
    }
    res.status(error.statusCode || 500).json({
        success: false,
        error: error?.message || "Internal Server Error.",
    });
};