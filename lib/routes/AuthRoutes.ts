import { Request, Response, NextFunction } from "express";
import { config } from "node-config-ts";
import { findIndex, difference } from "lodash";
import { Guid } from "guid-typescript";
import * as buildUrl from "build-url";
import * as Debug from "debug";
const debug = Debug("AuthServer:AuthRoutes:");
import * as Fs from "fs";
import { sign } from "jsonwebtoken";
import * as path from "path";
import IClient from "interfaces/IClient";
import Db from "../db/db";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { IRequest } from "../interfaces/IRequest";
import getRandomString from "../helpers/GetRandomString";
import { compare } from "bcryptjs";
import verifyCodeChallenge from "../helpers/VerifyCodeChallenge";

export class AuthRoutes {
    private db;

    public routes(app): void {
        this.db = app.Db;

        app.get("/", async(req: IRequest, res: Response) => {
            res.render("index",
            {
                title: "Authorization Server",
                endpoints: {
                    authorizationEndpoint: config.settings.authorizationEndpoint,
                    accessTokenEndpoint: config.settings.accessTokenEndpoint,
                    aliveEndpoint: config.settings.aliveEndpoint,
                },
            });
        });
        app.get("/alive", async(req: IRequest, res: Response) => {
            res.send("Success!");
        });
        app.get("/authorize", async(req: Request, res: Response) => {
             // 1. Verify ClientId
            let client: IClient = await this.db.getClient(((req?.query?.client_id ?? "") as string));

            if (config.settings.verifyClientId && !client) {
                res.render("authError",
                {
                    title: "Authorization Errors",
                    error: "Unknown Client Id.",
                });
                return;
            }

            // 2. Verify Redirect URL
            let redirectUrl = (req?.query?.redirect_uri ?? "").toString();
            let invalidRedirectUri = findIndex(client?.redirectUris ?? "", (r) => { return r === redirectUrl; }) < 0;

            if (config.settings.verifyRedirectUrl && invalidRedirectUri) {
                res.render("authError",
                {
                    title: "Authorization Errors",
                    error: "Invalid Redirect URL.",
                });
                return;
            }
            let queryScopes: string[];

            // 3. Verify Scope/s
            if (req?.query?.scopes) {
                let tmpScopes = Array.isArray(req.query.scopes) ? req.query.scopes?.toString() : ((req.query.scopes ?? "") as string);
                queryScopes = tmpScopes.split(",");
            }
            let openIdFlow = this.openIdFlow(queryScopes);
            let invalidScopes = this.verifyScope(queryScopes, client.scopes);

            if (config.settings.validateScope && invalidScopes) {
                res.redirect(
                    buildUrl(redirectUrl,
                    {
                        queryParams: { error: "Invalid Scope."},
                    }));

                return;
            }

            // 4. Create RequestId and store the request (if request should be validated...)
            let requestId = Guid.create();
            this.db.saveRequest(requestId, req?.query);

            // 5. Serve page and let user approve authorization (and possibly authenticate)
            let renderData = { client: client, requestId: requestId.toString(), scopes: queryScopes};

            if (openIdFlow) {
                res.render("authenticate", renderData);
            } else {
                res.render("allowRequest", renderData);
            }
        });

        app.post("/allowRequest", this.openIdRequest, this.authenticateUser, async(req: Request, res: Response) => {
            let query;
            let requestId;

            if (Guid.isGuid(req?.body?.request_id ?? "")) {
                requestId = Guid.parse(req?.body?.request_id ?? "");
                query = this.db.getRequest(requestId);
            }

            // Delete request id - mitigate replay
            if (config.settings.clearRequestId) {
                this.db.deleteRequest(requestId);
            }

            if (!query) {
                res.render("authError",
                {
                    title: "Authorization Errors",
                    error: "Could not find authorization request.",
                });

                return;
            }

            // If the user allowed the request
            if (req.body.allow) {
                const openIdRequest = req.body.openIdRequest;

                if (openIdRequest && !req.body.authenticated) {
                    res.render("authError",
                    {
                        title: "Authentication Error",
                        error: "Wrong credentials supplied.",
                    });
                    return;
                }

                // Authorization code request
                if (query.response_type === "code") {
                    // Verify scopes - should be the same as the clients scope
                    let selectedScopes = req.body.scopes;
                    let client = this.db.getClient(query.client_id);

                    let invalidScopes = this.verifyScope(selectedScopes, client.scopes);

                    if (config.settings.validateScope && invalidScopes) {
                        let url = buildUrl(query.redirect_uri, { queryParams: { error: "Invalid Scope"}});
                        res.redirect(url);

                        return;
                    }
                    let codeId = getRandomString(config.settings.authorizationCodeLength);
                    const request = { request: query, scopes: selectedScopes, userid: req.body.username };

                    this.db.saveAuthorizationCode(codeId, request);

                    if (this.isOpenIdConnectFlow(selectedScopes) && req.body?.username) {
                        this.db.updateUser(req.body.username,  Math.round((new Date()).getTime() / 1000), codeId);
                    }

                    let queryParams: any;

                    if (config.settings.verifyState) {
                        queryParams = {
                                queryParams: {
                                    state: query.state,
                                    code: codeId,
                                },
                            };
                    } else {
                        queryParams = {queryParams: { code: codeId }};
                    }
                    // Send the results back to the client
                    res.redirect(buildUrl(query.redirect_uri, queryParams));

                    return;
                } else {
                    res.redirect(buildUrl(query.redirect_uri, { queryParams: { error: "Invalid response type"}}));

                    return;
                    }
            } else {
                let url = buildUrl(query.redirect_uri, { queryParams: { error: "Access Denied."}});
                res.redirect(url);

                return;
            }
        });

        app.post("/token", async(req: Request, res: Response) => {
            let clientId: string;
            let clientSecret: string;

            if (req.body.client_id) {
                clientId = req.body.client_id;
                // if this is a public client client_secret will not be defined
                clientSecret = req.body.client_secret;
            } else {
                // TODO: Check header for clientId and secret
                // basic auth clientid:clientsecret	var headers = {
                // header "Authorization": "Basic "  + client_id ":" client_secret
                debug(`Client id or secret are invalid ${req.body.client_id}/`);
                res.status(401).send(`Client id or secret are invalid ${req.body.client_id}`);

                return;
            }

            let client: IClient = await this.db.getClient(clientId);

            if (!client) {
                debug(`Could not find client: ${clientId}`);
                res.status(401).send("Invalid client.");

                return;
            }
            if (!client.public && client.clientSecret !== clientSecret) {
                debug(`Invalid client secret: ${clientSecret}`);
                res.status(401).send("Invalid client secret.");

                return;
            }

            // 2. authorizationCode request =>
            if (req.body?.grant_type === config.settings.authorizationCodeGrant) {

                let code = this.getAuthorizationCode(req.body);

                // fresh or replayed token
                if (config.settings.verifyCode && !this.db.validAuthorizationCode(code)) {
                    debug(`Authorization Code is invalid (authorization_code/code): ${req.body.authorization_code} / ${req.body.code}`);
                    res.status(401).send("Invalid code.");

                    return;
                }

                let authorizationCodeRequest = this.db.getAuthorizationCode(code);

                if (authorizationCodeRequest) {
                    // remove code so it cannot be reused
                    if (config.settings.clearAuthorizationCode) {
                        this.db.deleteAuthorizationCode(code);
                    }

                    if (config.settings.verifyClientId && authorizationCodeRequest.request.client_id === clientId) {
                        let payload = await this.buildAccessToken(authorizationCodeRequest.scopes, authorizationCodeRequest?.userid);
                        let accessToken = this.signToken(payload);
                        let scopes = this.getScopesFromRequest(authorizationCodeRequest.request);
                        let openIdConnectFlow = this.isOpenIdConnectFlow(scopes);

                        // Verify PCKE - Stored hash should match hash of given code challenge
                        if (client.public && openIdConnectFlow && config.settings.usePkce) {
                            const codeChallenge = authorizationCodeRequest.request.code_challenge;
                            const reqCodeChallenge = req.body.code_challenge ?? req.body.code_verifier;

                            if (!verifyCodeChallenge(codeChallenge, reqCodeChallenge)) {
                                debug(`CodeChallenge does not matched stored CodeChallenge: ${reqCodeChallenge} / ${codeChallenge}`);
                                res.status(400).send("Invalid Code Challenge");
                                return;
                            }
                        }

                        if (config.settings.saveAccessToken) {
                            if (openIdConnectFlow) {
                                this.db.saveAccessTokenToUser(authorizationCodeRequest?.userid, accessToken);
                            } else {
                                this.db.saveAccessToken(accessToken, clientId);
                            }
                        }
                        let refreshToken = getRandomString(config.settings.refreshTokenLength);

                        if (openIdConnectFlow) {
                            this.db.saveRefreshTokenToUser(authorizationCodeRequest.userid, refreshToken, clientId, authorizationCodeRequest.scopes);
                        } else {
                            this.db.saveRefreshToken(refreshToken, clientId, authorizationCodeRequest.scopes, authorizationCodeRequest.userid);
                        }
                        let resultPayload = {access_token: accessToken, refresh_token: refreshToken, id_token: undefined };

                        if (openIdConnectFlow) {
                            let idToken = await this.buildIdToken(authorizationCodeRequest?.userid,  clientId, this.db);
                            resultPayload.id_token = this.signToken(idToken);
                            this.db.saveIdTokenToUser(authorizationCodeRequest?.userid, resultPayload.id_token);
                        }
                        res.status(200).send(resultPayload);

                        return;
                    } else {
                        debug(`Client id does not match stored client id: ${authorizationCodeRequest.request.client_id}/${clientId}`);
                        res.status(400).send("Invalid grant.");

                        return;
                    }
                } else {
                    debug(`Could not find code in storage ${authorizationCodeRequest}`);
                    res.status(400).send("Invalid grant.");

                return;
            }
            } else if (req.body.grant_type === config.settings.refreshTokenGrant) {
                // Check if we have the refresh token (with related data), i.e. valid refresh token
                let refreshTokenData = await this.db.getRefreshToken(req?.body?.refresh_token ?? "");

                if (refreshTokenData) {
                    debug("Verified refresh token.");

                    if (config.settings.verifyClientIdOnRefreshToken && refreshTokenData.clientId !== clientId) {
                         debug("Client mismatch on refresh token.");
                         res.status(400).send("Invalid client on refresh token.");

                        return;
                    }
                    let payload = await this.buildAccessToken(refreshTokenData.scopes, refreshTokenData.userId);
                    let accessToken = this.signToken(payload);

                    if (config.settings.saveAccessToken) {
                        if (refreshTokenData.userId) {
                            this.db.saveAccessTokenToUser(refreshTokenData.userId, accessToken);
                        } else {
                            this.db.saveAccessToken(accessToken, clientId);
                        }
                    }
                    res.status(200).send({access_token: accessToken, refresh_token: refreshTokenData.refreshToken });
                } else {
                    debug("Called with invalid refresh token.");
                    res.status(400).send("Called with invalid refresh token.");

                    return;
                }
            } else {
                debug("Called with invalid grant.");
                res.status(400).send("Invalid Grant.");

                return;
            }

            res.status(200).send();
        });
    }

    private getAuthorizationCode = (body: any): string => {
        return body.authorization_code ?? body.code;
    }

    private authenticateUser = async(req: IRequest, res: Response, next: NextFunction): Promise<any> => {

        if (req?.body?.openIdRequest) {
            let username = req?.body?.username;
            let user = await this.db.getUser(username);
            let password = req?.body?.password ? req?.body?.password : "";

            if (!user || password === "" || !user.enabled) {
                req.body.authenticated = false;
            } else {
                req.body.authenticated = await compare(password, user?.password);
            }
            next();
        }
        next();
    }

    // Shortcut: We're just checking if there are any user/password fields available in order
    // to decide if this is an openid request that needs authentication. In real life it would be
    // obvious when it is an authentication request.
    private openIdRequest = (req: IRequest, res: Response, next: NextFunction): any => {
        if (req?.body.username && req?.body.password) {
            req.body.openIdRequest = true;
        }
        next();
    }

    private isOpenIdConnectFlow = (scopes: any): boolean => {
        let tmpScopes = Array.isArray(scopes) ? scopes?.toString() : scopes;

        return tmpScopes.split(",").findIndex((x) => x === "openid") > -1;
    }

    // Create an id token for OpenId Connect flow
    private buildIdToken = async (email: string, clientId: string, db: Db): Promise<IVerifyOptions> => {
        let user = await db.getUser(email);

        return {
            iss: config.settings.issuer,
            sub: user?.email,
            aud: clientId,
            exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
            iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
            auth_time: user?.lastAuthenticated,
            nonce: user?.nonce,
        };
    }

    private openIdFlow = (queryScopes: string[]) => {
        return queryScopes?.includes("openid");
    }

    private getScopesFromRequest = (request: any) => {
        return request.scopes ?? request.scope;
    }

    // Verify that the client has all scopes that's asked for
    private verifyScope(askedScopes: string[], clientScopes: string[]): boolean {
       return difference(askedScopes, clientScopes).length > 0;
    }

    private buildAccessToken = async (scopes: [String], userid: String): Promise<IVerifyOptions> => {
        let user = await this.db.getUser(userid);
        let payload = {
            iss: config.settings.issuer,
            aud: config.settings.audience,
            sub: user?.userId ?? config.settings.subject,
            exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
            iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
            scope: scopes,
            email: user?.email,
            claims: user?.claims,
        };

        if (config.settings.addNonceToToken) {
            (payload as any).jti = getRandomString(16);
        }
        return payload;
    }

    private signToken = (options: IVerifyOptions): string => {
        return sign(options, Fs.readFileSync(path.join(__dirname, "../../config/key.pem")), { algorithm: config.settings.algorithm });
    }
}