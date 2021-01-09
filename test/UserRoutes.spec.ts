import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { VerifyOptions } from "jsonwebtoken";
import { expect } from "chai";
import { Response } from "express";
import UserModel from "../lib/db/UserModel";
import * as Debug from "debug";

interface IVerifyOptions extends VerifyOptions {
    iss: string;
    aud: string;
}
describe("User routes", () => {
    const testName: string = "TestName";
    const testPassword: string = "TestPassword";
    const testEmail: string = "TestEmail@test.nu";

    before( async() => {
        Debug.disable();
    });

    afterEach(async () => {
        await UserModel.collection.deleteMany({email: testEmail.toLowerCase()});
    });

    it("Should return 200 when adding a user", async () => {
        const response = await Supertest(app)
        .post("/users/create")
        .type("form")
        .send({
            name: testName,
            email: testEmail,
            password: testPassword,
        });
        expect(response.status).to.be.equal(200);
        expect(response.body.name).to.be.equal("TestName");
    });

    it("Should return 200 when login in a user", async () => {
        await addAUser();

        const response = await authenticateUser(testEmail, testPassword);

        expect(response.status).to.be.equal(200);
    });

    it("Should return 401 when trying to authenticate with wrong credentials", async () => {
        await addAUser();

        let response: Response = await authenticateUser(testEmail, "WrongPassword");

        expect(response.status).to.be.equal(401);
    });

    const authenticateUser = async (email, password): Promise<any> => {
        return await Supertest(app)
        .post("/users/authenticate")
        .type("form")
        .send({email: email, password: password});
    };

    const addAUser = async () => {
        await Supertest(app)
        .post("/users/create")
        .type("form")
        .send({
            name: testName,
            email: testEmail,
            password: testPassword,
        });
    };
});