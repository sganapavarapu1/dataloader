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

import com.salesforce.dataloader.client.transport.SimplePostInterface;
import org.apache.http.Header;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class JwtBearerFlowTest {

    private static class FakePost implements SimplePostInterface {
        final String endpoint;
        final BasicNameValuePair[] pairs;
        final int status;
        final String body;

        FakePost(String endpoint, BasicNameValuePair[] pairs, int status, String body) {
            this.endpoint = endpoint;
            this.pairs = pairs;
            this.status = status;
            this.body = body;
        }

        public void post() {}
        public boolean isSuccessful() { return status == 200; }
        public InputStream getInput() { return new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)); }
        public int getStatusCode() { return status; }
        public String getReasonPhrase() { return "reason"; }
        public Header[] getResponseHeaders(String headerName) { return new Header[0]; }
        public void addBasicNameValuePair(BasicNameValuePair pair) {}
    }

    private final List<FakePost> posts = new ArrayList<>();

    private JwtBearerFlow flow(int status, String body) {
        return new JwtBearerFlow(Clock.fixed(Instant.parse("2026-11-01T12:00:00Z"), ZoneOffset.UTC), (endpoint, pairs) -> {
            FakePost p = new FakePost(endpoint, pairs, status, body);
            posts.add(p);
            return p;
        });
    }

    private static PrivateKey key() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair().getPrivate();
    }

    @Test
    public void postsJwtBearerGrantToTokenEndpointAndReturnsTokenAndInstance() throws Exception {
        JwtBearerFlow f = flow(200, "{\"access_token\":\"TOKEN\",\"instance_url\":\"https://na1.my.salesforce.com\"}");
        JwtBearerFlow.Result r = f.requestToken(key(), "ck", "u@x.com", "https://login.salesforce.com", "https://login.salesforce.com/");

        assertEquals("TOKEN", r.accessToken);
        assertEquals("https://na1.my.salesforce.com", r.instanceUrl);
        FakePost p = posts.get(0);
        assertEquals("https://login.salesforce.com/services/oauth2/token", p.endpoint);
        assertEquals("grant_type", p.pairs[0].getName());
        assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", p.pairs[0].getValue());
        assertEquals("assertion", p.pairs[1].getName());
        assertEquals(3, p.pairs[1].getValue().split("\\.").length);
    }

    @Test
    public void errorResponseGivesActionableMessageWithoutLeakingAssertion() throws Exception {
        JwtBearerFlow f = flow(400, "{\"error\":\"invalid_grant\",\"error_description\":\"user hasn't approved this consumer\"}");
        try {
            f.requestToken(key(), "ck", "u@x.com", "https://login.salesforce.com", "https://login.salesforce.com");
            fail("expected exception");
        } catch (JwtBearerException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("invalid_grant"));
            assertTrue(e.getMessage(), e.getMessage().contains("pre-authorized"));
            assertFalse(e.getMessage().contains(posts.get(0).pairs[1].getValue()));
        }
    }

    @Test
    public void missingAccessTokenIsAnError() throws Exception {
        JwtBearerFlow f = flow(200, "{\"instance_url\":\"https://x\"}");
        try {
            f.requestToken(key(), "ck", "u", "aud", "https://login.salesforce.com");
            fail("expected exception");
        } catch (JwtBearerException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("access_token"));
        }
    }
}
