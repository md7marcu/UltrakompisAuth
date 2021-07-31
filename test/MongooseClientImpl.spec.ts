import "mocha";
import { expect } from "chai";
import { ClientModel } from "../lib/db/ClientModel";
import IClient from "../lib/interfaces/IClient";
import IAccessToken from "../lib/interfaces/IAccessToken";
import * as Debug from "debug";
import { decode } from "jsonwebtoken";
import MongoDb from "../lib/db/MongoDb";

// describe.skip("Test Mongoose impl.", () => {
describe("Test Mongoose Client impl.", () => {
    let accessToken: IAccessToken = {
        token: "testtoken",
        created: 1627662729,
        expires: 1627666359,
    };

    let client: IClient = {
        clientId: "Client4",
        clientSecret: "secret",
        redirectUris: ["redirecttome"],
        scope: ["clientScope1", "clientScope2"],
        enabled: true,
        accessTokens: [accessToken],
        refreshTokens: ["refreshToken"],
    };

    // tslint:disable-next-line:max-line-length
    let expiredAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRob3JpemUudWx0cmFrb21waXMuY29tIiwiYXVkIjoiYXBpLnVsdHJha29tcGlzLmNvbSIsInN1YiI6InVsdHJha29tcGlzIiwiZXhwIjoxNjEwNTk3NTg0LCJpYXQiOjE2MTA1OTM5NTQsInNjb3BlIjoib3BlbmlkIn0.Qfhvf7L9r7lYCQ3per6SKz6CJx-LPK_v-s94_KPvF-PQ9VerLe-90RfBAX8Xv9QWNK_UCDLAsvqvffBojS1ZB6wCxg6nLyAlNKSvODTDJp6pv4DOg43FeBIS-PEWmHXM1UfR6j0QvFJWra9KGS6LRB-ZopzGXPIgHOfsc6ThsMq8QA8C_9uqxMoMHszpm1B3cv7x6YZVL126D2znS1pBB6TVaf0IIcjnQYDjSo0hHykRQhiHfJ3k_1gsjpAIkZ3qyZq8rlr2n22mdweTsiqqGfSI2gBqkN3dfwuXRerD2u3MJd4wgzJ0Egp2ACSF8URG9WJ6uVQwaODp5H5ysf_vLw";
    let decodedExpiredAccessToken = (decode(expiredAccessToken) as any);

    before( async() => {
        Debug.disable();
    });

    afterEach( () => {
        ClientModel.collection.deleteMany({clientId: client.clientId});
    });

    it("Should save a client", async () => {
        let originalCount: number;
        await ClientModel.countDocuments({}, (error, count) => {
            originalCount = count;
        }).exec();

        let userModel = await new ClientModel(client).save();

        let newCount: number;
        await ClientModel.countDocuments({}, (error, count) => {
            newCount = count;
        }).exec();

        expect(originalCount + 1).to.be.equal(newCount);
    });

    it("Should remove expired accessTokens when saving a new token", async () => {
        await new ClientModel(client).save();
        await ClientModel.findOneAndUpdate({clientId: client.clientId},
            {$push: { accessTokens: { token: expiredAccessToken, created: decodedExpiredAccessToken.iat, expires: decodedExpiredAccessToken.exp}}});
        let iat = Date.now() / 1000 - 200;
        let exp = Date.now() / 1000 + 3600;
        let testAccessToken = "eyLen";

        await new MongoDb().saveClientAccessToken(client.clientId, testAccessToken, {exp: exp, iat: iat});
        let savedClient: IClient = await ClientModel.findOne({clientId: client.clientId}).lean();

        expect(savedClient.accessTokens[0].expires).to.equal(exp);
    });

    it("Should find a refresh token if it is available", async () => {
        await new ClientModel(client).save();
        let refreshToken = "eyLen";
        await ClientModel.findOneAndUpdate({clientId: client.clientId}, {$push: { refreshTokens: refreshToken}});

        let result = await new MongoDb().validateClientRefreshToken(refreshToken);

        // tslint:disable-next-line:no-unused-expression
        expect(result).to.be.true;
    });

    it("Should not find a refresh token if it is unavailable", async () => {
        await new ClientModel(client).save();
        let refreshToken = "eyLen";
        await ClientModel.findOneAndUpdate({clientId: client.clientId}, {$push: { refreshTokens: refreshToken}});

        let result = await new MongoDb().validateRefreshToken("not there");

        // tslint:disable-next-line:no-unused-expression
        expect(result).to.be.false;
    });
});
