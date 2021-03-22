import { Schema } from "mongoose";

export const ClientSchema: Schema = new Schema({
    clientId: {
        type: String,
        unique: true,
        required: true,
    },
    clientSecret: {
        type: String,
        required: false,
        unique: true,
    },
    redirectUris: [{
        type: String,
        required: false,
    }],
    scopes: [{
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
});