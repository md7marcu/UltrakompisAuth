import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { expect } from "chai";
import * as Debug from "debug";
import { config } from "node-config-ts";

describe("Server routes", () => {
    let wellKnownSettings;
    // let serverKid = "PInJ1JPDMcH4oXyI-1LJJpP6R3ezXdExCBHlVaIwjDc";
    let serverKid = "PCJRsp7ReGptQgyN6D_9OsqMZ9akBfKbrOW23iAaXtM";

    beforeEach( async() => {
        Debug.disable();
        wellKnownSettings = config.wellKnown;
        wellKnownSettings.issuer = config.settings.issuer;
        wellKnownSettings.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnownSettings.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnownSettings.jwks_uri = config.settings.jwksEndpoint;
        wellKnownSettings.userinfo_endpoint = "";
        wellKnownSettings.revocation_endpoint = "";
    });

    it("Should return 200 when retrieving well-known", async () => {
        let testWellKnown = JSON.stringify(wellKnownSettings);
        const response = await Supertest(app)
            .get("/.well-known/openid-configuration");
        expect(JSON.stringify(JSON.parse(response.text))).to.be.equal(testWellKnown);
    });

    it("Should return 200 and server certificate", async () => {
        let response = await Supertest(app)
        .get("/oauth2/certs");

        expect(response.status).equal(200);
        expect(JSON.parse(response.text).keys[0].kid).to.be.equal(serverKid);
    });
});