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

    it ("Should return undefined if the client doesn't exist", () => {
        // tslint:disable-next-line:no-unused-expression
        expect(new Db().getClient("-1")).to.be.empty;
    });

    it ("Should return the client", async () => {
        let client = await new Db().getClient("ukauth-client");

        assert.equal(client.scopes[0], "ssn");
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
        let scopes = ["c", "b"];
        let db = new Db();
        db.saveRefreshTokenToUser("user.name", refreshToken, clientId, scopes);

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
});