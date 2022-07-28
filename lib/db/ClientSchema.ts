import { Schema } from "mongoose";

export const clientSchema: Schema = new Schema({
    clientId: {
        type: String,
        unique: true,
        required: true,
    },
    clientSecret: {
        type: String,
        required: false,
    },
    redirectUris: [{
        type: String,
        required: false,
    }],
    scope: [{
        type: String,
    }],
    enabled: {
        type: Boolean,
        default: false,
    },
    public: {
        type: Boolean,
        required: false,
    },
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
        type: String,
    }],
});