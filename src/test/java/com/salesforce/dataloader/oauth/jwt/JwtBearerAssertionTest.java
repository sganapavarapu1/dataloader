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
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class JwtBearerAssertionTest {

    private static final Instant NOW = Instant.parse("2026-11-01T12:00:00Z");

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static JsonObject part(String jwt, int idx) {
        String json = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[idx]), StandardCharsets.UTF_8);
        return JsonParser.parseString(json).getAsJsonObject();
    }

    @Test
    public void headerIsRs256AndClaimsAreSet() throws Exception {
        KeyPair kp = newKeyPair();
        JwtBearerAssertion a = new JwtBearerAssertion(kp.getPrivate(), Clock.fixed(NOW, ZoneOffset.UTC));
        String jwt = a.create("consumerKey", "user@example.com", "https://login.salesforce.com");

        assertEquals("RS256", part(jwt, 0).get("alg").getAsString());
        JsonObject c = part(jwt, 1);
        assertEquals("consumerKey", c.get("iss").getAsString());
        assertEquals("user@example.com", c.get("sub").getAsString());
        assertEquals("https://login.salesforce.com", c.get("aud").getAsString());
        assertEquals(NOW.getEpochSecond() + 180, c.get("exp").getAsLong());
        assertFalse(c.get("jti").getAsString().isEmpty());
    }

    @Test
    public void signatureVerifiesWithPublicKeyAndNoPadding() throws Exception {
        KeyPair kp = newKeyPair();
        String jwt = new JwtBearerAssertion(kp.getPrivate(), Clock.fixed(NOW, ZoneOffset.UTC))
                .create("k", "u", "https://login.salesforce.com");
        assertFalse(jwt.contains("="));
        String[] p = jwt.split("\\.");
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(kp.getPublic());
        s.update((p[0] + "." + p[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(s.verify(Base64.getUrlDecoder().decode(p[2])));
    }

    @Test
    public void eachAssertionHasAFreshJti() throws Exception {
        JwtBearerAssertion a = new JwtBearerAssertion(newKeyPair().getPrivate(), Clock.fixed(NOW, ZoneOffset.UTC));
        String j1 = part(a.create("k", "u", "aud"), 1).get("jti").getAsString();
        String j2 = part(a.create("k", "u", "aud"), 1).get("jti").getAsString();
        assertNotEquals(j1, j2);
    }
}
