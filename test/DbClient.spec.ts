import { expect, assert } from "chai";
import Db from "../lib/db/db";
import { config } from "node-config-ts";
import * as Debug from "debug";

describe ("Client Auth Static Db implementation", () => {
    let testClient = {
        clientId: "testClient123",
        clientSecret: "secret",
        redirectUris: ["http:"],
        scope: ["email"],
        public: false,
        enabled: true,
    };
    let db: Db;

    before( async() => {
        Debug.disable();
        config.settings.useMongo = false;
    });

    beforeEach( async() => {
        db = new Db();
        await db.addClient(testClient.clientId, testClient.clientSecret,
                           testClient.redirectUris, testClient.scope, testClient.public);
    });

    it ("Should return undefined if the client doesn't exist", () => {
        // tslint:disable-next-line:no-unused-expression
        expect(new Db().getClient("-1")).to.be.empty;
    });

    it ("Should return the client", async () => {
        let client = await new Db().getClient("ukauth-client");

        assert.equal(client.scope[0], "ssn");
    });

    it ("Should save a client refresh token", async () => {
        let refreshToken = "token321";

        db.saveClientRefreshToken(refreshToken, testClient.clientId);
        let client = await db.getClient(testClient.clientId);

        assert.equal(client.refreshTokens[0], refreshToken);
    });

    it ("Should save a client access token", async () => {
        let accessToken = "token321";

        db.saveClientAccessToken(accessToken, testClient.clientId);
        let client = await db.getClient(testClient.clientId);

        assert.equal((client as any).accessTokens[0], accessToken);
    });
});