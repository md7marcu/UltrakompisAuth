import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { expect } from "chai";
import * as Debug from "debug";
import { config } from "node-config-ts";

describe("Server routes", () => {
    let wellKnown;

    before( async() => {
        Debug.disable();
        console.log(config.settings);
        wellKnown = config.wellKnown;
        wellKnown.issuer = "";
        wellKnown.authorization_endpoint = config.settings.authorizationEndpoint;
        wellKnown.token_endpoint = config.settings.accessTokenEndpoint;
        wellKnown.userinfo_endpoint = "";
        wellKnown.revocation_endpoint = "";
    });

    it("Should return 200 when retrieving well-known", async () => {
        const response = await Supertest(app)
            .get("/.well-known/openid-configuration");
        expect(JSON.stringify(JSON.parse(response.text))).to.be.equal(JSON.stringify(wellKnown));
    });
});