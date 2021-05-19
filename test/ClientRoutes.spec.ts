import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { VerifyOptions } from "jsonwebtoken";
import { expect } from "chai";
import * as Debug from "debug";
import ClientModel from "../lib/db/ClientModel";

interface IVerifyOptions extends VerifyOptions {
    iss: string;
    aud: string;
}
describe("Client routes", () => {
    const testClientId: string = "TestClientId";
    const testClientSecret: string = "TestClientSecret";
    const testRedirectUris: string = "localhost";
    const testScope: string = "scope";
    const testPublic: boolean = true;

    let client = {
        clientId: testClientId,
        clientSecret: testClientSecret,
        redirectUris: testRedirectUris,
        scope: testScope,
        public: testPublic,
        enabled: true,
    };
    before( async() => {
        Debug.disable();

        if (process.env.NODE_ENV === "test") {
            await ClientModel.collection.deleteMany({clientId: client.clientId.toLowerCase()});
        }
    });

    afterEach(async () => {
        if (process.env.NODE_ENV === "test") {
            await ClientModel.collection.deleteMany({clientId: client.clientId.toLowerCase()});
        }
    });

    it("Should return 200 when adding a client", async () => {
        const response = await Supertest(app)
        .post("/client/create")
        .type("form")
        .send({
            clientId: testClientId,
            clientSecret: testClientSecret,
            redirectUris: testRedirectUris,
            scope: testScope,
            public: testPublic,
        });
        expect(response.status).to.be.equal(200);
        expect(response.body.clientId).to.be.equal(testClientId);
    });
});