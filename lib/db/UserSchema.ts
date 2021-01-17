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
    idTokens: [{
        token: {
            type: String,
        },
        created: {
            type: Number,
        },
        expires: {
            type: Number,
        },
    }],
    accessTokens: [{
        token: {
            type: String,
        },
        created: {
            type: Number,
        },
        expires: {
            type: Number,
        },
    }],
    refreshTokens: [{
        token: {
            type: String,
        },
        created: {
            type: Number,
        },
        expires: {
            type: Number,
        },
        clientId: {
            type: String,
        },
        scopes: {
            type: [String],
        },
        userId: {
            type: String,
        },
    }],
    claims: [{
        type: String,
    }],
    code: String,
    nonce: String,
    lastAuthenticated: String,
    enabled: { type: Boolean, default: false},
});