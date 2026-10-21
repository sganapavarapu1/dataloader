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


package com.salesforce.dataloader.process;

import com.salesforce.dataloader.config.AppConfig;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The browser (PKCE) login must run only when nothing else can authenticate a batch run.
 */
public class ProcessRunnerOAuthLoginTest {

    private AppConfig config(boolean hasUsername, boolean hasPassword, String accessToken, String jwtKeyFile) {
        AppConfig appConfig = mock(AppConfig.class);
        when(appConfig.contains(AppConfig.PROP_USERNAME)).thenReturn(hasUsername);
        when(appConfig.contains(AppConfig.PROP_PASSWORD)).thenReturn(hasPassword);
        when(appConfig.getString(AppConfig.PROP_OAUTH_ACCESSTOKEN)).thenReturn(accessToken);
        when(appConfig.getString(AppConfig.PROP_OAUTH_JWT_KEYFILE)).thenReturn(jwtKeyFile);
        return appConfig;
    }

    @Test
    public void browserLoginIsRequiredWhenNoCredentialsAreConfigured() {
        assertTrue(ProcessRunner.requiresOAuthLogin(config(true, false, "", "")));
    }

    @Test
    public void browserLoginIsNotRequiredWithUsernameAndPassword() {
        assertFalse(ProcessRunner.requiresOAuthLogin(config(true, true, "", "")));
    }

    @Test
    public void browserLoginIsNotRequiredWhenAnAccessTokenIsConfigured() {
        assertFalse(ProcessRunner.requiresOAuthLogin(config(true, false, "00Dxx0000006Gi7!token", "")));
    }

    @Test
    public void browserLoginIsNotRequiredWhenJwtBearerIsConfigured() {
        assertFalse(ProcessRunner.requiresOAuthLogin(config(true, false, "", "/secure/dl.key.pem")));
    }
}
