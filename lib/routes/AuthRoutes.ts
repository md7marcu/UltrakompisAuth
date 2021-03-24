import { Request, Response, NextFunction } from "express";
import { config } from "node-config-ts";
import { findIndex, difference } from "lodash";
import { Guid } from "guid-typescript";
import * as buildUrl from "build-url";
import * as Debug from "debug";
const debug = Debug("AuthServer:AuthRoutes:");
import IClient from "interfaces/IClient";
import Db from "../db/db";
import { IVerifyOptions } from "../interfaces/IVerifyOptions";
import { IRequest } from "../interfaces/IRequest";
import getRandomString from "../helpers/GetRandomString";
import { compare } from "bcryptjs";
import verifyCodeChallenge from "../helpers/VerifyCodeChallenge";
import { ClientCredentialsController } from "../controllers/ClientCredentialsController";
import signToken from "../helpers/SignToken";
import { TokenExchangeController } from "../controllers/TokenExchangeController";

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
            let queryScope: string[];

            let scope = this.getScopeFromRequest(req?.query);
            // 3. Verify Scope/s
            if (scope) {
                let tmpScope = Array.isArray(scope) ? scope?.toString() : ((scope ?? "") as string);
                queryScope = tmpScope.split(",");
            }
            let openIdFlow = this.openIdFlow(queryScope);
            let invalidScope = this.verifyScope(queryScope, client.scope);

            if (config.settings.validateScope && invalidScope) {
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
            let renderData = { client: client, requestId: requestId.toString(), scope: queryScope};

            if (openIdFlow) {
                res.render("authenticate", renderData);
            } else {
                res.render("allowRequest", renderData);
            }
        });

        app.post("/allowRequest", this.authenticateUser, async(req: Request, res: Response) => {
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
            if (req?.body?.allow) {
                let selectedScope =  this.getScopeFromRequest(req?.body);

                if (selectedScope && this.isOpenIdConnectFlow(selectedScope) && !req.body.authenticated) {
                    res.render("authError",
                    {
                        title: "Authentication Error",
                        error: "Wrong credentials supplied.",
                    });
                    return;
                }

                // Authorization code request
                if (query.response_type === "code") {
                    // Verify scope - should be the same as the clients scope
                    let client = await this.db.getClient(query.client_id);

                    let invalidScope = this.verifyScope(selectedScope, client.scope);

                    if (config.settings.validateScope && invalidScope) {
                        let url = buildUrl(query.redirect_uri, { queryParams: { error: "Invalid Scope"}});
                        res.redirect(url);

                        return;
                    }
                    let codeId = getRandomString(config.settings.authorizationCodeLength);
                    const request = { request: query, scope: selectedScope, userid: req.body.username };

                    this.db.saveAuthorizationCode(codeId, request);

                    if (this.isOpenIdConnectFlow(selectedScope) && req.body?.username) {
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

            if (req.body?.grant_type === config.settings.clientCredentialsGrant) {
                let clientCredentialsController = new ClientCredentialsController();
                let token = await clientCredentialsController.getTokens(this.db, req?.headers?.authorization, app.httpsOptions.key);

                if (token === undefined){
                    res.status(401).send("Unknown Client or invalid Secret");
                } else {
                    res.status(200).send(token);
                }
                return;
            }

            if (req.body?.grant_type === config.settings.tokenExchangeGrant) {
                let tokenExchangeController = new TokenExchangeController();
                let token = await tokenExchangeController.getTokens(this.db, req?.headers?.authorization, req?.body, app.httpsOptions.key, app.httpsOptions.cert);

                if (token === undefined) {
                    res.status(400).send("Unknown error for token exchange.");
                } else {
                    res.status(200).send(token);
                }
                return;
            }

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
                        let payload = await this.buildAccessToken(authorizationCodeRequest.scope, authorizationCodeRequest?.userid);
                        let accessToken = signToken(payload, app.httpsOptions.key);
                        let scope = this.getScopeFromRequest(authorizationCodeRequest.request);
                        let openIdConnectFlow = this.isOpenIdConnectFlow(scope);

                        // Verify PCKE - Stored hash should match hash of given code challenge
                        if (config.settings.usePkce &&
                            (authorizationCodeRequest.request.code_challenge || authorizationCodeRequest.request.code_verifier)) {

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
                            this.db.saveRefreshTokenToUser(authorizationCodeRequest.userid, refreshToken, clientId, authorizationCodeRequest.scope);
                        } else {
                            this.db.saveRefreshToken(refreshToken, clientId, authorizationCodeRequest.scope, authorizationCodeRequest.userid);
                        }
                        let resultPayload = {access_token: accessToken, refresh_token: refreshToken, id_token: undefined };

                        if (openIdConnectFlow) {
                            let idToken = await this.buildIdToken(authorizationCodeRequest?.userid,  clientId, this.db);
                            resultPayload.id_token = signToken(idToken, app.httpsOptions.key);
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
                    let payload = await this.buildAccessToken(refreshTokenData.scope, refreshTokenData.userId);
                    let accessToken = signToken(payload, app.httpsOptions.key);

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

    private isOpenIdConnectFlow = (scope: any): boolean => {
        let tmpScope = Array.isArray(scope) ? scope?.toString() : scope;

        return tmpScope.split(",").findIndex((x) => x === "openid") > -1;
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

    private openIdFlow = (queryScope: string[]) => {
        return queryScope?.includes("openid");
    }

    private getScopeFromRequest = (request: any) => {
        return request.scope ?? request.scope;
    }

    // Verify that the client has all scope that's asked for
    private verifyScope(askedScope: string[], clientScope: string[]): boolean {
       return difference(askedScope, clientScope).length > 0;
    }

    private buildAccessToken = async (scope: [String], userid: String): Promise<IVerifyOptions> => {
        let user = await this.db.getUser(userid);
        let payload = {
            iss: config.settings.issuer,
            aud: config.settings.audience,
            sub: user?.email ?? config.settings.subject,
            exp: Math.floor(Date.now() / 1000) + config.settings.expiryTime,
            iat: Math.floor(Date.now() / 1000) - config.settings.createdTimeAgo,
            scope: scope,
            email: user?.email,
            claims: user?.claims,
        };

        if (config.settings.addNonceToToken) {
            (payload as any).jti = getRandomString(16);
        }
        return payload;
    }
}