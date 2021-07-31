import "mocha";
import { expect } from "chai";
import { UserModel } from "../lib/db/UserModel";
import IUser from "../lib/interfaces/IUser";
import * as Debug from "debug";
import { decode } from "jsonwebtoken";
import MongoDb from "../lib/db/MongoDb";

// describe.skip("Test Mongoose impl.", () => {
describe("Test Mongoose impl.", () => {
    let user: IUser = {
        userId: "1234",
        name: "Test",
        password: "secret",
        email: "test@test.nu",
    };

    // tslint:disable-next-line:max-line-length
    let expiredAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRob3JpemUudWx0cmFrb21waXMuY29tIiwiYXVkIjoiYXBpLnVsdHJha29tcGlzLmNvbSIsInN1YiI6InVsdHJha29tcGlzIiwiZXhwIjoxNjEwNTk3NTg0LCJpYXQiOjE2MTA1OTM5NTQsInNjb3BlIjoib3BlbmlkIn0.Qfhvf7L9r7lYCQ3per6SKz6CJx-LPK_v-s94_KPvF-PQ9VerLe-90RfBAX8Xv9QWNK_UCDLAsvqvffBojS1ZB6wCxg6nLyAlNKSvODTDJp6pv4DOg43FeBIS-PEWmHXM1UfR6j0QvFJWra9KGS6LRB-ZopzGXPIgHOfsc6ThsMq8QA8C_9uqxMoMHszpm1B3cv7x6YZVL126D2znS1pBB6TVaf0IIcjnQYDjSo0hHykRQhiHfJ3k_1gsjpAIkZ3qyZq8rlr2n22mdweTsiqqGfSI2gBqkN3dfwuXRerD2u3MJd4wgzJ0Egp2ACSF8URG9WJ6uVQwaODp5H5ysf_vLw";
    let decodedExpiredAccessToken = (decode(expiredAccessToken) as any);

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

    it("Should remove expired accessTokens when saving a new token", async () => {
        await new UserModel(user).save();
        await UserModel.findOneAndUpdate({email: user.email},
            {$push: { accessTokens: { token: expiredAccessToken, created: decodedExpiredAccessToken.iat, expires: decodedExpiredAccessToken.exp}}});
        let iat = Date.now() / 1000 - 200;
        let exp = Date.now() / 1000 + 3600;
        let accessToken = "eyLen";

        await new MongoDb().saveAccessTokenToUser(user.email, accessToken, {exp: exp, iat: iat});
        let savedUser: IUser = await UserModel.findOne({email: user.email}).lean();

        expect(savedUser.accessTokens[0].expires).to.equal(exp);
    });

    it("Should remove expired idToken when saving a new token", async () => {
        await new UserModel(user).save();
        await UserModel.findOneAndUpdate({email: user.email},
            {$push: { idTokens: { token: expiredAccessToken, created: decodedExpiredAccessToken.iat, expires: decodedExpiredAccessToken.exp}}});
        let iat = Date.now() / 1000 - 200;
        let exp = Date.now() / 1000 + 3600;
        let accessToken = "eyLen";

        await new MongoDb().saveIdTokenToUser(user.email, accessToken, {exp: exp, iat: iat});
        let savedUser: IUser = await UserModel.findOne({email: user.email}).lean();

        expect(savedUser.idTokens[0].expires).to.equal(exp);
    });

    it("Should remove expired refreshToken when saving a new token", async () => {
        await new UserModel(user).save();
        await UserModel.findOneAndUpdate({email: user.email},
            {$push: { refreshTokens: { token: expiredAccessToken, created: decodedExpiredAccessToken.iat, expires: decodedExpiredAccessToken.exp,
                clientId: undefined, scope: undefined, email: undefined}}});
        let iat = Date.now() / 1000 - 200;
        let exp = Date.now() / 1000 + 3600;
        let accessToken = "eyLen";

        await new MongoDb().saveRefreshTokenToUser(user.email, accessToken, iat, exp, undefined, undefined);
        let savedUser: IUser = await UserModel.findOne({email: user.email}).lean();

        expect(savedUser.refreshTokens[0].expires).to.equal(exp);
    });

    it("Should find a refresh token if it is available", async () => {
        await new UserModel(user).save();
        let refreshToken = "eyLen";
        await UserModel.findOneAndUpdate({email: user.email},
            {$push: { refreshTokens: { token: refreshToken, created: decodedExpiredAccessToken.iat, expires: decodedExpiredAccessToken.exp,
                clientId: undefined, scope: undefined, email: undefined}}});

        let result = await new MongoDb().validateRefreshToken(refreshToken);

        // tslint:disable-next-line:no-unused-expression
        expect(result).to.be.true;
    });

    it("Should not find a refresh token if it is unavailable", async () => {
        await new UserModel(user).save();
        let refreshToken = "eyLen";
        await UserModel.findOneAndUpdate({email: user.email},
            {$push: { refreshTokens: { token: refreshToken, created: decodedExpiredAccessToken.iat, expires: decodedExpiredAccessToken.exp,
                clientId: undefined, scope: undefined, email: undefined}}});

        let result = await new MongoDb().validateRefreshToken("not there");

        // tslint:disable-next-line:no-unused-expression
        expect(result).to.be.false;
    });
});
