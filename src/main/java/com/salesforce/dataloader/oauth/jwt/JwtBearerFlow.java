/*
 * Copyright (c) 2015, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.salesforce.dataloader.oauth.jwt;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.salesforce.dataloader.client.transport.SimplePostInterface;
import org.apache.http.message.BasicNameValuePair;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.function.BiFunction;

/**
 * Exchanges a signed assertion for an access token at /services/oauth2/token (OAuth 2.0 JWT Bearer grant).
 * No browser, no local socket, no UI classes: safe to run in headless batch mode.
 */
public class JwtBearerFlow {
    static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    static final String TOKEN_PATH = "/services/oauth2/token";

    public static final class Result {
        public final String accessToken;
        public final String instanceUrl;

        Result(String accessToken, String instanceUrl) {
            this.accessToken = accessToken;
            this.instanceUrl = instanceUrl;
        }
    }

    private final Clock clock;
    private final BiFunction<String, BasicNameValuePair[], SimplePostInterface> postFactory;

    public JwtBearerFlow(Clock clock, BiFunction<String, BasicNameValuePair[], SimplePostInterface> postFactory) {
        this.clock = clock;
        this.postFactory = postFactory;
    }

    public Result requestToken(PrivateKey key, String clientId, String username, String audience, String tokenHost)
            throws JwtBearerException {
        String assertion;
        try {
            assertion = new JwtBearerAssertion(key, clock).create(clientId, username, audience);
        } catch (GeneralSecurityException e) {
            throw new JwtBearerException("Cannot sign the JWT assertion with the configured private key: " + e.getMessage(), e);
        }
        String host = tokenHost.endsWith("/") ? tokenHost.substring(0, tokenHost.length() - 1) : tokenHost;
        SimplePostInterface post = postFactory.apply(host + TOKEN_PATH, new BasicNameValuePair[] {
                new BasicNameValuePair("grant_type", GRANT_TYPE),
                new BasicNameValuePair("assertion", assertion)});
        try {
            post.post();
            JsonObject body = readJson(post.getInput());
            if (!post.isSuccessful()) {
                throw new JwtBearerException(describeFailure(post.getStatusCode(), body, username));
            }
            if (body == null || !body.has("access_token")) {
                throw new JwtBearerException("The token response did not contain an access_token");
            }
            String instance = body.has("instance_url") ? body.get("instance_url").getAsString() : null;
            return new Result(body.get("access_token").getAsString(), instance);
        } catch (IOException | com.salesforce.dataloader.exception.ParameterLoadException e) {
            throw new JwtBearerException("JWT Bearer token request to " + host + TOKEN_PATH + " failed: " + e.getMessage(), e);
        }
    }

    private static JsonObject readJson(InputStream in) {
        try {
            if (in == null) {
                return null;
            }
            return JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String describeFailure(int status, JsonObject body, String username) {
        String error = body != null && body.has("error") ? body.get("error").getAsString() : "HTTP " + status;
        String desc = body != null && body.has("error_description") ? body.get("error_description").getAsString() : "";
        String hint;
        switch (error) {
            case "invalid_grant":
                hint = "Check that " + username + " is pre-authorized for the External Client App (permission set), "
                        + "that the uploaded certificate matches the private key, and that the audience matches the login URL.";
                break;
            case "invalid_client_id":
            case "invalid_client":
                hint = "Check sfdc.oauth.jwt.clientid: it must be the External Client App's consumer key.";
                break;
            case "invalid_app_access":
                hint = "The user is not pre-authorized for this External Client App.";
                break;
            default:
                hint = "Check the External Client App's JWT Bearer settings (scopes api and refresh_token, certificate uploaded).";
        }
        return "JWT Bearer login failed: " + error + (desc.isEmpty() ? "" : " - " + desc) + ". " + hint;
    }
}
