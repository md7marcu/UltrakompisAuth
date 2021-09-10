import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { expect } from "chai";
import * as Debug from "debug";
import { config } from "node-config-ts";
import setHttpsOptions from "./helpers/certs";
import { buildAndSignToken } from "./helpers/token";

describe("Server routes", () => {
    let wellKnownOpenIdSettings;
    let wellKnownServerSettings;
    let serverKid = "localhost";
    let user = {
        userId: "12345678",
        email: "user@email.com",
        name: "Email Juarez",
        password: "",
    };
    let lapp = app;

    beforeEach( async() => {
        Debug.disable();
        wellKnownOpenIdSettings = config.wellKnown;
        wellKnownOpenIdSettings.issuer = config.settings.issuer;
        wellKnownOpenIdSettings.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownOpenIdSettings.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownOpenIdSettings.userinfo_endpoint = config.settings.userinfoEndpoint;
        wellKnownOpenIdSettings.jwks_uri = config.settings.jwksEndpoint;
        wellKnownOpenIdSettings.revocation_endpoint = "";

        wellKnownServerSettings = config.wellKnown;
        wellKnownServerSettings.issuer = config.settings.issuer;
        wellKnownServerSettings.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownServerSettings.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownServerSettings.scopes_supported = config.settings.scopes_supported;
        wellKnownServerSettings.jwks_uri = config.settings.jwksEndpoint;
        wellKnownServerSettings.userinfo_endpoint = config.settings.userinfoEndpoint;
        wellKnownServerSettings.revocation_endpoint = "";
        wellKnownServerSettings.token_endpoint_auth_signing_alg_values_supported = config.settings.jwkAlgorithm;
        wellKnownServerSettings.introspection_endpoint = config.settings.introspectionEndpoint;

        setHttpsOptions(app);
    });

    it("Should return 200 when retrieving well-known", async () => {
        let testWellKnown = JSON.stringify(wellKnownOpenIdSettings);
        const response = await Supertest(app)
            .get("/.well-known/openid-configuration");
        expect(JSON.stringify(JSON.parse(response.text))).to.be.equal(testWellKnown);
    });

    it("Should return 200 when retrieving well-known server", async () => {
        let testWellKnown = JSON.stringify(wellKnownOpenIdSettings);
        const response = await Supertest(app)
            .get("/.well-known/oauth-authorization-server");
        expect(JSON.stringify(JSON.parse(response.text))).to.be.equal(testWellKnown);
    });

    it("Should return 200 and server certificate", async () => {
        let response = await Supertest(app)
        .get("/oauth2/certs");

        expect(response.status).equal(200);
        expect(JSON.parse(response.text).keys[0].kid).to.be.equal(serverKid);
    });

    it("Should return 200 and user info on GET to userinfo endpoint", async () => {
        let token = await buildAndSignToken(user, app.httpsOptions.key);

        let response = await Supertest(app).get("/userinfo").set("Authorization", token);

        expect(response.status).equal(200);
        expect(JSON.parse(response.text).email).to.be.equal(user.email);
    });

    it("Should return 200 and user info on POST to userinfo endpoint", async () => {
        let token = await buildAndSignToken(user, app.httpsOptions.key);

        let response = await Supertest(app).post("/userinfo").set("Authorization", token);

        expect(response.status).equal(200);
        expect(JSON.parse(response.text).email).to.be.equal(user.email);
    });
});