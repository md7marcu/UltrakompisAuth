/* eslint-disable @typescript-eslint/naming-convention */
import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { VerifyOptions } from "jsonwebtoken";
import * as Debug from "debug";
import { expect } from "chai";
import { config } from "node-config-ts";
import * as path from "path";

interface IVerifyOptions extends VerifyOptions {
    iss: string;
    aud: string[];
}
describe("OIDC authorization code flow", () => {
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

    it("Should return 200 and error if client id is missing", async () => {
        const response = await Supertest(app).get("/authorize").query(
            {

            });
        expect(response.status).to.be.equal(200);
        expect(response.text).to.contain("Unknown Client Id.");
    });

    it("Should start the OIDC flow if called with code and scope equal to openid", async () => {
        const response = await Supertest(app).get("/authorize").query(
            {
                client_id: config.settings.clients[1].clientId,
                redirect_uri: config.settings.clients[1].redirectUris[0],
                response_type: "code",
                scope: ["openid"],
            });
        expect(response.status).to.be.equal(200);
    });
});