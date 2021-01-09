import "mocha";
import { expect } from "chai";
import { UserModel } from "../lib/db/UserModel";
import IUser from "../lib/interfaces/IUser";
import * as Debug from "debug";

describe.skip("Test Mongoose impl.", () => {
    let user: IUser = {
        name: "Test",
        password: "secret",
        email: "test@test.nu",
    };

    before( async() => {
        Debug.disable();
    });

    afterEach( () => {
        UserModel.collection.deleteMany({email: user.email});
    });

    it("Should save a user", async () => {
        let originalCount: number;
        await UserModel.countDocuments({}, (error, count) => {
            originalCount = count;
        }).exec();

        let userModel = await new UserModel(user).save();

        let newCount: number;
        await UserModel.countDocuments({}, (error, count) => {
            newCount = count;
        }).exec();

        expect(originalCount + 1).to.be.equal(newCount);
    });

    it("Added user should not be enabled", async () => {
        let userModel = await new UserModel(user).save();

        // tslint:disable-next-line:no-unused-expression
        expect(userModel.enabled).to.be.false;
    });
});