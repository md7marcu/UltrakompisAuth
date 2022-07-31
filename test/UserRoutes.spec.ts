import "mocha";
import * as Supertest from "supertest";
import app  from "../lib/app";
import { VerifyOptions } from "jsonwebtoken";
import { expect } from "chai";
import { Response } from "express";
import userModel from "../lib/db/UserModel";
import * as Debug from "debug";

interface IVerifyOptions extends VerifyOptions {
    iss: string;
    aud: string[];
}
describe("User routes", () => {
    const testName: string = "TestName";
    const testPassword: string = "TestPassword";
    const testEmail: string = "TestEmail@test.nu";

    let user = {
        userId: "12345678",
        password: "verysecret#",
        email: "user@email.com",
        name: "Email Juarez",
        claims: ["duh", "lol"],
        enabled: true,
    };

    let inactivatedUser = {
        userId: "123",
        password: "vidkun",
        email: "inactivatedUser@email.com",
        name: "Vidqkun Q.",
        claims: ["test"],
        enabled: false,
        activationCode: "45",
    };

    const authenticateUser = async (email, password): Promise<any> => {
        return await Supertest(app)
            .post("/users/authenticate")
            .type("form")
            .send({email: email, password: password});
    };

    beforeEach( async() => {
        Debug.disable();

        if (process.env.NODE_ENV === "test") {
            await userModel.collection.deleteMany({email: user.email.toLowerCase()});
            await userModel.collection.deleteMany({email: inactivatedUser.email.toLowerCase()});
        }
        await new userModel(user).save();
        await new userModel(inactivatedUser).save();
    });

    afterEach(async () => {
        if (process.env.NODE_ENV === "test") {
            await userModel.collection.deleteMany({email: testEmail.toLowerCase()});
            await userModel.collection.deleteMany({email: user.email.toLowerCase()});
            await userModel.collection.deleteMany({email: inactivatedUser.email.toLowerCase()});
        }
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

        let result = await userModel.findOne({email: testEmail}).lean();

        expect(result.email).to.be.equal(testEmail.toLowerCase());
        expect(response.status).to.be.equal(200);
        expect(response.body.name).to.be.equal("TestName");
    });

    it("Should return 200 when login in a user", async () => {
        const response = await authenticateUser(user.email, user.password);

        expect(response.status).to.be.equal(200);
    });

    it("Should return 401 when trying to authenticate with wrong credentials", async () => {
        let response: Response = await authenticateUser(user.email, "WrongPassword");

        expect(response.status).to.be.equal(401);
    });

    it("Should return 200 when activating a user", async () => {
        const response = await Supertest(app)
            .post("/users/activate")
            .send({
                email: inactivatedUser.email,
                activationCode: inactivatedUser.activationCode,
            });
        expect(response.status).to.be.equal(200);
        let result = await userModel.findOne({email: inactivatedUser.email}).lean();

        // eslint-disable-next-line @typescript-eslint/no-unused-expressions, no-unused-expressions
        expect(result.enabled).to.be.true;
    });

});