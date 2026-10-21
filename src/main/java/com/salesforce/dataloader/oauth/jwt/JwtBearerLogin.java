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

import com.salesforce.dataloader.client.transport.SimplePostFactory;
import com.salesforce.dataloader.client.transport.SimplePostInterface;
import com.salesforce.dataloader.config.AppConfig;
import org.apache.http.message.BasicNameValuePair;

import java.security.PrivateKey;
import java.time.Clock;
import java.util.function.BiFunction;

/**
 * Headless login for batch runs: reads the sfdc.oauth.jwt.* settings, runs the JWT Bearer grant and stores the
 * resulting access token and instance URL where the rest of Data Loader already looks for them.
 * Can be called again at any time to mint a fresh token.
 */
public class JwtBearerLogin {
    static final String FLOW_NAME = "JWT Bearer";

    private final AppConfig appConfig;
    private final JwtBearerFlow flow;

    public JwtBearerLogin(AppConfig appConfig, Clock clock, BiFunction<String, BasicNameValuePair[], SimplePostInterface> postFactory) {
        this.appConfig = appConfig;
        this.flow = new JwtBearerFlow(clock, postFactory);
    }

    public static JwtBearerLogin forConfig(AppConfig appConfig) {
        return new JwtBearerLogin(appConfig, Clock.systemUTC(),
                (endpoint, pairs) -> SimplePostFactory.getInstance(appConfig, endpoint, pairs));
    }

    /** The key file's presence turns JWT Bearer mode on. */
    public static boolean isConfigured(AppConfig appConfig) {
        String keyFile = appConfig.getString(AppConfig.PROP_OAUTH_JWT_KEYFILE);
        return keyFile != null && !keyFile.isBlank();
    }

    public void authenticate() throws JwtBearerException {
        String username = required(appConfig.getString(AppConfig.PROP_USERNAME), AppConfig.PROP_USERNAME);
        String clientId = appConfig.getString(AppConfig.PROP_OAUTH_JWT_CLIENTID);
        if (clientId == null || clientId.isBlank()) {
            clientId = appConfig.getECAClientIdForCurrentEnv();
        }
        required(clientId, AppConfig.PROP_OAUTH_JWT_CLIENTID);

        String loginHost = appConfig.getAuthEndpointForCurrentEnv();
        String audience = appConfig.getString(AppConfig.PROP_OAUTH_JWT_AUDIENCE);
        if (audience == null || audience.isBlank()) {
            audience = loginHost;
        }

        PrivateKey key;
        try {
            key = PemPrivateKeyLoader.load(appConfig.getString(AppConfig.PROP_OAUTH_JWT_KEYFILE),
                    appConfig.getString(AppConfig.PROP_OAUTH_JWT_KEYPASSWORD));
        } catch (IllegalArgumentException e) {
            throw new JwtBearerException(e.getMessage(), e);
        }
        JwtBearerFlow.Result result = flow.requestToken(key, clientId, username, audience, loginHost);
        appConfig.setValue(AppConfig.PROP_OAUTH_ACCESSTOKEN, result.accessToken);
        if (result.instanceUrl != null) {
            appConfig.setValue(AppConfig.PROP_OAUTH_INSTANCE_URL, result.instanceUrl);
        }
        appConfig.setLastOAuthFlow(FLOW_NAME);
    }

    private static String required(String value, String propertyName) throws JwtBearerException {
        if (value == null || value.isBlank()) {
            throw new JwtBearerException("JWT Bearer login needs " + propertyName + " to be set");
        }
        return value;
    }
}
