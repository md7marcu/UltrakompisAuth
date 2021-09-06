import { Request, Response, NextFunction  } from "express";
import { IRequest } from "../interfaces/IRequest";
import * as Debug from "debug";
const debug = Debug("AuthServer:AuthController");
import Db from "../db/db";
import { config } from "node-config-ts";
import IClient from "interfaces/IClient";
import { findIndex, difference } from "lodash";
import * as buildUrl from "build-url";
import { Guid } from "guid-typescript";
import getRandomString from "../helpers/GetRandomString";
import { IApplication } from "app";
import { ClientCredentialsController } from "../controllers/ClientCredentialsController";
import signToken from "../helpers/SignToken";
import { TokenExchangeController } from "../controllers/TokenExchangeController";
import verifyCodeChallenge from "../helpers/VerifyCodeChallenge";
import { buildUserAccessToken } from "../helpers/BuildAccessToken";
import buildIdToken from "../helpers/BuildIdToken";
import { ErrorResponse } from "../helpers/ErrorResponse";
import IUser from "interfaces/IUser";

export class AuthController {

    public async root(req: IRequest, res: Response, next: NextFunction) {
        res.render("index",
        {
            title: "Authorization Server",
            endpoints: {
                authorizationEndpoint: config.settings.authorizationEndpoint,
                accessTokenEndpoint: config.settings.accessTokenEndpoint,
                aliveEndpoint: config.settings.aliveEndpoint,
            },
        });
    }

    public async alive(req: IRequest, res: Response, next: NextFunction) {
        res.send("Success!");
    }

    public async authorize(req: IRequest, res: Response, next: NextFunction, database: Db) {
        // 1. Verify ClientId
        let client: IClient = await database.getClient(((req?.query?.client_id ?? "") as string));

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
        database.saveRequest(requestId, req?.query);

        // 5. Serve page and let user approve authorization (and possibly authenticate)
        let renderData = { client: client, requestId: requestId.toString(), scope: queryScope};

        if (openIdFlow) {
            res.render("authenticate", renderData);
        } else {
            res.render("allowRequest", renderData);
        }
    }

    public async allowRequest(req: Request, res: Response, next: NextFunction, database: Db) {
        let query;
        let requestId;

        if (Guid.isGuid(req?.body?.request_id ?? "")) {
            requestId = Guid.parse(req?.body?.request_id ?? "");
            query = database.getRequest(requestId);
        }

        // Delete request id - mitigate replay
        if (config.settings.clearRequestId) {
            database.deleteRequest(requestId);
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
                let client = await database.getClient(query.client_id);

                let invalidScope = this.verifyScope(selectedScope, client.scope);

                if (config.settings.validateScope && invalidScope) {
                    let url = buildUrl(query.redirect_uri, { queryParams: { error: "Invalid Scope"}});
                    res.redirect(url);

                    return;
                }
                let codeId = getRandomString(config.settings.authorizationCodeLength);
                const request = { request: query, scope: selectedScope, email: req.body.username };

                database.saveAuthorizationCode(codeId, request);

                if (this.isOpenIdConnectFlow(selectedScope) && req.body?.username) {
                    database.updateUser(req.body.username,  Math.round((new Date()).getTime() / 1000), codeId);
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
    }

    public async token(req: Request, res: Response, next: NextFunction, app: IApplication) {
        let clientId: string;
        let clientSecret: string;

        if (req.body?.grant_type === config.settings.clientCredentialsGrant) {
            let clientCredentialsController = new ClientCredentialsController();
            let token = await clientCredentialsController.getTokens(app.Db, req?.headers?.authorization, app.httpsOptions.key);

            if (token === undefined) {
                next(new ErrorResponse("Unknown Client or invalid Secret", 401));
            } else {
                res.status(200).send(token);
            }
            return;
        }

        if (req.body?.grant_type === config.settings.tokenExchangeGrant) {
            let tokenExchangeController = new TokenExchangeController();
            let token = await tokenExchangeController.getTokens(app.Db, req?.headers?.authorization,
                                                                req?.body, app.httpsOptions.key, app.httpsOptions.cert);

            if (token === undefined) {
                next(new ErrorResponse("Unknown error for token exchange.", 401));
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
            next(new ErrorResponse(`Client id or secret are invalid ${req.body.client_id}`, 401));

            return;
        }

        let client: IClient = await app.Db.getClient(clientId);

        if (!client) {
            debug(`Could not find client: ${clientId}`);
            next(new ErrorResponse("Invalid client.", 401));

            return;
        }
        if (!client.public && client.clientSecret !== clientSecret) {
            debug(`Invalid client secret: ${clientSecret}`);
            next(new ErrorResponse("Invalid client secret.", 401));

            return;
        }

        // 2. authorizationCode request =>
        if (req.body?.grant_type === config.settings.authorizationCodeGrant) {

            let code = this.getAuthorizationCode(req.body);

            // fresh or replayed token
            if (config.settings.verifyCode && !app.Db.validAuthorizationCode(code)) {
                debug(`Authorization Code is invalid (authorization_code/code): ${req.body.authorization_code} / ${req.body.code}`);
                next(new ErrorResponse("Invalid code.", 401));

                return;
            }

            let authorizationCodeRequest = app.Db.getAuthorizationCode(code);

            if (authorizationCodeRequest) {
                // remove code so it cannot be reused
                if (config.settings.clearAuthorizationCode) {
                    app.Db.deleteAuthorizationCode(code);
                }

                if (config.settings.verifyClientId && authorizationCodeRequest.request.client_id === clientId) {
                    let user = await app.Db.getUserByEmail(authorizationCodeRequest?.email);
                    let accessToken: string;

                    if (config.settings.opaqueAccessToken) {
                        accessToken = Guid.create().toString();
                    } else {
                        let payload = await buildUserAccessToken(authorizationCodeRequest.scope, clientId, user);
                        accessToken = signToken(payload, app.httpsOptions.key);
                    }
                    let scope = this.getScopeFromRequest(authorizationCodeRequest.request);
                    let openIdConnectFlow = this.isOpenIdConnectFlow(scope);

                    // Verify PCKE - Stored hash should match hash of given code challenge
                    if (config.settings.usePkce &&
                        (authorizationCodeRequest.request.code_challenge || authorizationCodeRequest.request.code_verifier)) {

                        const codeChallenge = authorizationCodeRequest.request.code_challenge;
                        const reqCodeChallenge = req.body.code_challenge ?? req.body.code_verifier;

                        if (!verifyCodeChallenge(codeChallenge, reqCodeChallenge)) {
                            debug(`CodeChallenge does not matched stored CodeChallenge: ${reqCodeChallenge} / ${codeChallenge}`);
                            next(new ErrorResponse("Invalid Code Challenge.", 400));

                            return;
                        }
                    }

                    if (config.settings.saveAccessToken) {
                        if (openIdConnectFlow) {
                            app.Db.saveAccessTokenToUser(authorizationCodeRequest?.email, accessToken);
                        } else {
                            app.Db.saveAccessToken(accessToken, clientId);
                        }
                    }
                    let refreshToken = getRandomString(config.settings.refreshTokenLength);

                    if (openIdConnectFlow) {
                        app.Db.saveRefreshTokenToUser(authorizationCodeRequest.email, refreshToken, clientId, authorizationCodeRequest.scope);
                    } else {
                        app.Db.saveRefreshToken(refreshToken, clientId, authorizationCodeRequest.scope, authorizationCodeRequest.email);
                    }
                    let resultPayload = {access_token: accessToken, refresh_token: refreshToken, id_token: undefined };

                    if (openIdConnectFlow) {
                        await this.createIdToken(clientId, user, app, authorizationCodeRequest?.email);
                    }

                    // TODO: Handle opaque tokens properly
                    // If we're doing opaque access token - do not return refresh and id token
                    if (config.settings.opaqueAccessToken) {
                        // resultPayload.id_token = undefined; have to return id_token
                        // oidc-client - refresh_token silent renew
                        // resultPayload.refresh_token = undefined;
                    }
                    res.status(200).send(resultPayload);

                    return;
                } else {
                    debug(`Client id does not match stored client id: ${authorizationCodeRequest.request.client_id}/${clientId}`);
                    next(new ErrorResponse("Invalid grant.", 400));

                    return;
                }
            } else {
                debug(`Could not find code in storage ${authorizationCodeRequest}`);
                next(new ErrorResponse("Invalid grant.", 400));

                return;
            }
        } else if (req.body.grant_type === config.settings.refreshTokenGrant) {
            // Check if we have the refresh token (with related data), i.e. valid refresh token
            let refreshTokenData = await app.Db.getRefreshToken(req?.body?.refresh_token ?? "");

            if (refreshTokenData) {
                debug("Verified refresh token.");

                if (config.settings.verifyClientIdOnRefreshToken && refreshTokenData.clientId !== clientId) {
                     debug("Client mismatch on refresh token.");
                     next(new ErrorResponse("Invalid client on refresh token.", 400));

                    return;
                }
                let user = await app.Db.getUserByEmail(refreshTokenData.email);
                let accessToken: string;

                if (config.settings.opaqueAccessToken) {
                    accessToken = Guid.create().toString();
                } else {
                    let payload = await buildUserAccessToken(refreshTokenData.scope, clientId, user);
                    accessToken = signToken(payload, app.httpsOptions.key);
                }

                if (config.settings.saveAccessToken) {
                    if (refreshTokenData.email) {
                        app.Db.saveAccessTokenToUser(refreshTokenData.email, accessToken);
                    } else {
                        app.Db.saveAccessToken(accessToken, clientId);
                    }
                }
                let idToken = await this.createIdToken(clientId, user, app, refreshTokenData?.email);
                res.status(200).send({access_token: accessToken, refresh_token: refreshTokenData.token, id_token: idToken });
            } else {
                debug("Called with invalid refresh token.");
                next(new ErrorResponse("Called with invalid refresh token.", 400));

                return;
            }
        } else {
            debug("Called with invalid grant.");
            next(new ErrorResponse("Invalid grant.", 400));

            return;
        }
        res.status(200).send();
    }

    private getAuthorizationCode = (body: any): string => {
        return body.authorization_code ?? body.code;
    }

    private isOpenIdConnectFlow = (scope: any): boolean => {
        let tmpScope = Array.isArray(scope) ? scope?.toString() : scope;

        return tmpScope.split(",").findIndex((x) => x === "openid") > -1;
    }

    private openIdFlow = (queryScope: string[]) => {
        return queryScope?.includes("openid");
    }

    private getScopeFromRequest = (request: any) => {
        return request.scope ?? request.scopes;
    }

    private async createIdToken(clientId: string, user: IUser, app: IApplication, email: string): Promise<string> {
        let idToken = await buildIdToken(clientId, user);
        // tslint:disable-next-line:variable-name
        let id_token: string;

        // TODO: Handle opaque tokens 'properly'
        // Remove claims from id token
        if (config.settings.opaqueAccessToken) {
            idToken.claims = undefined;
            id_token = signToken(idToken, app.httpsOptions.key);
        } else {
            id_token = signToken(idToken, app.httpsOptions.key);
        }
        app.Db.saveIdTokenToUser(email, id_token);

        return id_token;
    }

    // Verify that the client has all scope that's asked for
    private verifyScope(askedScope: string[], clientScope: string[]): boolean {
       return difference(askedScope, clientScope).length > 0;
    }
}
export const authController = new AuthController();