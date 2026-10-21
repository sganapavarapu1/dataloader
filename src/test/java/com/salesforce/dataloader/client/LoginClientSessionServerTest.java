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


package com.salesforce.dataloader.client;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * On the OAuth token path the session server (used for Bulk and REST calls) must be the instance
 * the token was issued for, never the login host.
 */
public class LoginClientSessionServerTest {

    @Test
    public void instanceUrlWithPathIsReducedToSchemeAndAuthority() {
        assertEquals("https://na1.my.salesforce.com",
                LoginClient.getSessionServerFromInstanceUrl("https://na1.my.salesforce.com/services/Soap/u/64.0"));
    }

    @Test
    public void portIsKept() {
        assertEquals("https://org.my.localhost.sfdcdev.salesforce.com:6101",
                LoginClient.getSessionServerFromInstanceUrl("https://org.my.localhost.sfdcdev.salesforce.com:6101/"));
    }

    @Test
    public void unsetAndInvalidValuesGiveNull() {
        assertNull(LoginClient.getSessionServerFromInstanceUrl(null));
        assertNull(LoginClient.getSessionServerFromInstanceUrl(""));
        // AppConfig's default for the instance URL property is the string "false"
        assertNull(LoginClient.getSessionServerFromInstanceUrl("false"));
        assertNull(LoginClient.getSessionServerFromInstanceUrl("ftp://example.com"));
    }
}
