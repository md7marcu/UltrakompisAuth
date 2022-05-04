import { Schema } from "mongoose";
import isEmail  from "validator/lib/isEmail";
import { hashSync, genSaltSync } from "bcryptjs";

export const userSchema: Schema = new Schema({
    userId: {
        type: String,
        required: true,
        unique: true,
    },
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
        scope: {
            type: [String],
        },
        email: {
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

userSchema.pre("save", function(next) {
    let user: any = this;
    // only hash the password if it has been modified (or is new)
    if (!user.isModified("password")) {
        return next();
    }

    // generate a salt
    let salt = genSaltSync(10);
    let hash = hashSync(user.password, salt);
    // override the cleartext password with the hashed one
    user.password = hash;
    next();
});