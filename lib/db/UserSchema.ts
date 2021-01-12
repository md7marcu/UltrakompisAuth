import { Schema } from "mongoose";
import isEmail  from "validator/lib/isEmail";

export const UserSchema: Schema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: [isEmail, "Invalid Email address"],
    },
    password: {
        type: String,
        required: true,
    },
    tokens: [{
        token: {
            type: String,
        },
    }],
    code: String,
    nonce: String,
    lastAuthenticated: String,
    enabled: { type: Boolean, default: false},
});