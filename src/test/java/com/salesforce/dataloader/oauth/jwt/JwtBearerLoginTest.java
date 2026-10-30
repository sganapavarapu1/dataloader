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
import com.salesforce.dataloader.config.AppConfig;
import org.apache.http.Header;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JwtBearerLoginTest {

    private AppConfig cfg;
    private final List<String> endpoints = new ArrayList<>();
    private final List<BasicNameValuePair[]> posted = new ArrayList<>();

    @Before
    public void setUp() throws Exception {
        cfg = mock(AppConfig.class);
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_KEYFILE)).thenReturn(
                new File(getClass().getClassLoader().getResource("jwt/test-key-plain.pem").toURI()).getPath());
        when(cfg.getString(AppConfig.PROP_USERNAME)).thenReturn("u@example.com");
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_CLIENTID)).thenReturn("explicitKey");
        when(cfg.getAuthEndpointForCurrentEnv()).thenReturn("https://login.salesforce.com");
    }

    private JwtBearerLogin login() {
        return new JwtBearerLogin(cfg, Clock.systemUTC(), (endpoint, pairs) -> {
            endpoints.add(endpoint);
            posted.add(pairs);
            return new SimplePostInterface() {
                public void post() {}
                public boolean isSuccessful() { return true; }
                public InputStream getInput() {
                    return new ByteArrayInputStream("{\"access_token\":\"NEWTOKEN\",\"instance_url\":\"https://na1.my.salesforce.com\"}"
                            .getBytes(StandardCharsets.UTF_8));
                }
                public int getStatusCode() { return 200; }
                public String getReasonPhrase() { return "OK"; }
                public Header[] getResponseHeaders(String n) { return new Header[0]; }
                public void addBasicNameValuePair(BasicNameValuePair p) {}
            };
        });
    }

    private JsonObject claims() {
        String assertion = posted.get(0)[1].getValue();
        return JsonParser.parseString(new String(Base64.getUrlDecoder().decode(assertion.split("\\.")[1]), StandardCharsets.UTF_8))
                .getAsJsonObject();
    }

    @Test
    public void isConfiguredOnlyWhenKeyFileIsSet() {
        assertTrue(JwtBearerLogin.isConfigured(cfg));
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_KEYFILE)).thenReturn("  ");
        assertFalse(JwtBearerLogin.isConfigured(cfg));
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_KEYFILE)).thenReturn(null);
        assertFalse(JwtBearerLogin.isConfigured(cfg));
    }

    @Test
    public void authenticateStoresTokenAndInstanceUrl() throws Exception {
        login().authenticate();
        verify(cfg).setValue(AppConfig.PROP_OAUTH_ACCESSTOKEN, "NEWTOKEN");
        verify(cfg).setValue(AppConfig.PROP_OAUTH_INSTANCE_URL, "https://na1.my.salesforce.com");
        verify(cfg).setLastOAuthFlow("JWT Bearer");
    }

    @Test
    public void assertionUsesConfiguredClientIdUsernameAndLoginHostAsAudience() throws Exception {
        login().authenticate();
        assertEquals("https://login.salesforce.com/services/oauth2/token", endpoints.get(0));
        assertEquals("explicitKey", claims().get("iss").getAsString());
        assertEquals("u@example.com", claims().get("sub").getAsString());
        assertEquals("https://login.salesforce.com", claims().get("aud").getAsString());
    }

    @Test
    public void explicitAudienceOverridesTheDefault() throws Exception {
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_AUDIENCE)).thenReturn("https://test.salesforce.com");
        login().authenticate();
        assertEquals("https://test.salesforce.com", claims().get("aud").getAsString());
        assertEquals("https://login.salesforce.com/services/oauth2/token", endpoints.get(0));
    }

    @Test
    public void clientIdFallsBackToExternalClientAppConfiguration() throws Exception {
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_CLIENTID)).thenReturn("");
        when(cfg.getECAClientIdForCurrentEnv()).thenReturn("ecaKey");
        login().authenticate();
        assertEquals("ecaKey", claims().get("iss").getAsString());
    }

    @Test
    public void missingClientIdOrUsernameIsReported() {
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_CLIENTID)).thenReturn("");
        when(cfg.getECAClientIdForCurrentEnv()).thenReturn("");
        try {
            login().authenticate();
            fail("expected exception");
        } catch (JwtBearerException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(AppConfig.PROP_OAUTH_JWT_CLIENTID));
        }
        when(cfg.getString(AppConfig.PROP_OAUTH_JWT_CLIENTID)).thenReturn("k");
        when(cfg.getString(AppConfig.PROP_USERNAME)).thenReturn("");
        try {
            login().authenticate();
            fail("expected exception");
        } catch (JwtBearerException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(AppConfig.PROP_USERNAME));
        }
    }
}
