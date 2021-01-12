import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { VerifyOptions } from "jsonwebtoken";
import * as Debug from "debug";
import { expect } from "chai";
import { config } from "node-config-ts";
import * as path from "path";
import { Guid } from "guid-typescript";

interface IVerifyOptions extends VerifyOptions {
    iss: string;
    aud: string;
}
describe("Express routes", () => {
    let db = (app as any).Db;

    before( async() => {
        Debug.disable();
    });

    beforeEach(() => {
        // Setup fake rendering
        app.set("views", path.join(__dirname, "../lib/views"));
        app.set("view engine", "pug");
        app.engine("pug", (viewpath, options, callback) => {
            const details = Object.assign( { viewpath }, options);
            callback(undefined, JSON.stringify(details));
        });
    });

    it("Should return 200 on alive endpoint", async () => {
        const response = await Supertest(app).get("/alive");

        expect(response.status).to.be.equal(200);
    });

    it("Should render error on authorize endpoint when called without client id", async () => {
        const response = await Supertest(app).get("/authorize");

        expect(response.status).to.be.equal(200);
        expect(response.text).to.contain("Unknown Client Id.");
    });

    it("Should render error on authorize endpoint when called without redirect url", async () => {
        const response = await Supertest(app).get("/authorize").query({ client_id: config.settings.clients[0].clientId });

        expect(response.status).to.be.equal(200);
        expect(response.text).to.contain("Invalid Redirect URL.");
    });

    it("Should redirect to callback when authorize endpoint called with invalid scope", async () => {
        const response = await Supertest(app).get("/authorize").query(
            {
                client_id: config.settings.clients[0].clientId,
                redirect_uri: config.settings.clients[0].redirectUris[0],
                scopes: ["non existing"],
            });

        expect(response.status).to.be.equal(302);
        expect(response.text).to.contain("Invalid%20Scope.");
    });

    it("Should render allowRequest page when call is successful", async () => {
        const response = await Supertest(app).get("/authorize").query(
            {
                client_id: config.settings.clients[0].clientId,
                redirect_uri: config.settings.clients[0].redirectUris[0],
                scopes: ["ssn"],
            });

        expect(response.status).to.be.equal(200);
        expect(response.text).to.contain("allowRequest");
    });

    it("Should render error when allowRequest endpoint is called with non existing request id", async () => {
        const response = await Supertest(app).post("/allowRequest");

        expect(response.status).to.be.equal(200);
        expect(response.text).to.contain("Could not find authorization request.");
    });

    it("Should redirect to callback with error if allowed not passed in", async () => {
        let requestId = Guid.create();
        db.saveRequest(requestId, {redirect_uri: "https://localhost:3002/"});

        const response = await Supertest(app)
        .post("/allowRequest")
        .send(`request_id=${requestId}`)
        .type("form")
        .set("Accept", "application/json");

        expect(response.status).to.be.equal(302);
        expect(JSON.stringify(response.header)).to.contain("Access%20Denied.");
    });

    it("Should return 401 if client id is missing", async () => {
        const response = await Supertest(app)
        .post("/token")
        .type("form");

        expect(response.status).to.be.equal(401);
    });

    it("Should return 401 if client secret is invalid", async () => {
        const response = await Supertest(app)
        .post("/token")
        .type("form")
        .send(
            {
                client_id: config.settings.clients[0].clientId,
                client_secret: "invalid secret",
            });

        expect(response.status).to.be.equal(401);
        expect(response.text).to.contain("Invalid client secret.");
    });

    it("Should return 400 if grant type is invalid", async () => {
        const response = await Supertest(app)
        .post("/token")
        .type("form")
        .send(
            {
                client_id: config.settings.clients[0].clientId,
                client_secret: config.settings.clients[0].clientSecret,
            });

        expect(response.status).to.be.equal(400);
        expect(response.text).to.contain("Invalid Grant.");
    });

    it("Should return 401 if supplied code is not valid", async () => {
        const response = await Supertest(app)
        .post("/token")
        .type("form")
        .send(
            {
                client_id: config.settings.clients[0].clientId,
                client_secret: config.settings.clients[0].clientSecret,
                grant_type: config.settings.authorizationCodeGrant,
                code: "invalidCode",
            });

        expect(response.status).to.be.equal(401);
        expect(response.text).to.contain("Invalid code.");
    });

    it("Should return 200 and token", async () => {
        let code = "abc123";
        let clientId = config.settings.clients[0].clientId;
        db.saveAuthorizationCode(code, {request: {client_id: clientId, scopes: "ssn"}});

        const response = await Supertest(app)
        .post("/token")
        .type("form")
        .send(
            {
                client_id: clientId,
                client_secret: config.settings.clients[0].clientSecret,
                grant_type: config.settings.authorizationCodeGrant,
                authorization_code: code,
            });

        expect(response.status).to.be.equal(200);
        expect(response.text).to.contain("refresh_token");
    });

    // Not very good test, hacks too much
    it("Should return 400 when called with refresh_token grant with erroneous clientId", async () => {
        let code = "abc123";
        let clientId = config.settings.clients[0].clientId;
        db.saveAuthorizationCode(code, {request: {clientId: clientId, scopes: ["ssn"]}});
        db.saveRefreshToken("cba321", "3232", ["ssn"]);

        const response = await Supertest(app)
        .post("/token")
        .type("form")
        .send(
            {
                client_id: clientId,
                client_secret: config.settings.clients[0].clientSecret,
                grant_type: config.settings.refreshTokenGrant,
                refresh_token: "cba321",
            });

        expect(response.status).to.be.equal(400);
        expect(response.text).to.contain("Invalid refresh token.");
    });

    it("Should return new access token upon refresh", async () => {
        let code = "abc123";
        let clientId = config.settings.clients[0].clientId;
        let refreshToken = "cba321-2";
        db.saveAuthorizationCode(code, {request: {clientId: clientId, scopes: ["ssn"]}});
        db.saveRefreshToken(refreshToken, clientId, ["ssn"]);

        const response = await Supertest(app)
        .post("/token")
        .type("form")
        .send(
            {
                client_id: clientId,
                client_secret: config.settings.clients[0].clientSecret,
                grant_type: config.settings.refreshTokenGrant,
                refresh_token: refreshToken,
            });

        expect(response.status).to.be.equal(200);

        // tslint:disable-next-line:no-unused-expression
        expect(db.validAccessToken(JSON.parse(response.text).access_token)).to.be.true;
    });
});