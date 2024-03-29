/* eslint-disable @typescript-eslint/no-unused-expressions */
/* eslint-disable no-unused-expressions */
import { expect, assert } from "chai";
import Db from "../lib/db/db";
import { Guid } from "guid-typescript";
import { config } from "node-config-ts";
import { compare} from "bcryptjs";
import * as Debug from "debug";

describe ("Static Db implementation", () => {
    before( async() => {
        Debug.disable();
        config.settings.useMongo = false;
    });

    it ("Should save a request", () => {
        let guid = Guid.create();
        let db = new Db();
        db.saveRequest(guid, "test");
        let request = db.getRequest(guid);

        assert.equal(request, "test");
    });

    it ("Should save a code", () => {
        let codeId = "code123";
        let codeData = {object: "obj"};
        let db = new Db();
        db.saveAuthorizationCode(codeId, codeData);

        // tslint:disable-next-line:no-unused-expression
        expect(db.validAuthorizationCode(codeId)).to.be.true;
        assert.equal(db.getAuthorizationCode(codeId).object, "obj");
    });

    it ("Should return invalid authorization code if it doesn't exist", () => {
        let db = new Db();
        let code = db.validAuthorizationCode("Elefant");

        // tslint:disable-next-line:no-unused-expression
        expect(code).to.be.false;
    });

    it ("Should delete an authorization code", () => {
        let db = new Db();
        let code = "code 321";
        db.saveAuthorizationCode(code, {});

        let valid = db.validAuthorizationCode("code");

        // tslint:disable-next-line:no-unused-expression
        expect(valid).to.be.false;
    });

    it("Should delete a request", () => {
        let db = new Db();
        let guid = Guid.create();

        db.saveRequest(guid, "{query: anyQuery}");
        db.deleteRequest(guid);

        let request = db.getRequest(guid);

        // tslint:disable-next-line:no-unused-expression
        expect(request).to.be.empty.string;
    });

    it ("Should save a refresh token", async () => {
        let refreshToken = "token321";
        let clientId = "Client23";
        let scope = ["c", "b"];
        let db = new Db();
        db.saveRefreshTokenToUser("user.name", refreshToken, clientId, scope);

        let validToken = await db.validRefreshToken(refreshToken);
        let refreshTokenData = await db.getRefreshToken(refreshToken);

        // tslint:disable-next-line:no-unused-expression
        expect(validToken).to.be.true;
        assert.equal(refreshTokenData.clientId, clientId);
    });

    it ("Should add a user and return it", async () => {
        let db = new Db();
        let user = await db.addUser("ken", "ken@ken.nu", "ken", undefined);

        expect(user.name).to.equal("ken");
    });

    it ("Should hash the password when adding a user", async () => {
        let db = new Db();
        let user = await db.addUser("test", "test@test.se", "test", undefined);

        let isMatch = await compare("test", user.password);

        // tslint:disable-next-line:no-unused-expression
        expect(isMatch).to.be.true;
    });

    it ("Should activate a user", async () => {
        let db = new Db();
        const email = "kaka@kaka.nu";
        let user = await db.addUser("ken", email, "ken", undefined);
        let activationCode = user.activationCode;
        let beforeActivation = user.enabled;

        await db.activateUser(email, activationCode);
        let activatedUser = await db.getUserByEmail(email);
        let afterActivation = activatedUser.enabled;

        expect(activationCode).not.undefined;
        expect(activatedUser.activationCode).to.be.undefined;
        expect(beforeActivation).to.be.false;
        expect(afterActivation).to.be.true;
    });

    it ("Should get user by access code.", async () => {
        let db = new Db();
        const email = "kaka@ken.nu";
        const token = "test2";
        await db.addUser("ken", email, "ken", undefined);
        await db.saveAccessTokenToUser(email, token);

        let updatedUser = await db.getUserByAccessToken(token);

        expect(updatedUser.email).equal(email);
    });
});