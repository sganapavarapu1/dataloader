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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PemPrivateKeyLoaderTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    private File write(String content) throws Exception {
        File f = tmp.newFile();
        Files.write(f.toPath(), content.getBytes(StandardCharsets.US_ASCII));
        return f;
    }

    @Test
    public void loadsPlainPkcs8() throws Exception {
        KeyPair kp = newKeyPair();
        File f = write(pem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        PrivateKey loaded = PemPrivateKeyLoader.load(f.getPath(), null);
        assertArrayEquals(kp.getPrivate().getEncoded(), loaded.getEncoded());
    }

    private static String fixture(String name) throws Exception {
        return new File(PemPrivateKeyLoaderTest.class.getClassLoader().getResource("jwt/" + name).toURI()).getPath();
    }

    // fixtures were produced by the real openssl tools customers will use; all hold the same key
    @Test
    public void loadsEncryptedPkcs8FromLibreSsl() throws Exception {
        PrivateKey expected = PemPrivateKeyLoader.load(fixture("test-key-plain.pem"), null);
        assertArrayEquals(expected.getEncoded(), PemPrivateKeyLoader.load(fixture("test-key-encrypted.pem"), "s3cret").getEncoded());
    }

    @Test
    public void loadsEncryptedPkcs8FromOpenSsl3() throws Exception {
        PrivateKey expected = PemPrivateKeyLoader.load(fixture("test-key-plain.pem"), null);
        assertArrayEquals(expected.getEncoded(), PemPrivateKeyLoader.load(fixture("test-key-encrypted-openssl3.pem"), "s3cret").getEncoded());
    }

    @Test
    public void wrongPasswordIsReported() throws Exception {
        try {
            PemPrivateKeyLoader.load(fixture("test-key-encrypted.pem"), "wrong");
            fail("expected exception");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("wrong password"));
        }
    }

    @Test
    public void encryptedKeyWithoutPasswordIsRejectedWithHint() throws Exception {
        File f = write(pem("ENCRYPTED PRIVATE KEY", new byte[] {1, 2, 3}));
        try {
            PemPrivateKeyLoader.load(f.getPath(), "");
            fail("expected exception");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("sfdc.oauth.jwt.keypassword"));
        }
    }

    @Test
    public void pkcs1KeyIsRejectedWithConversionHint() throws Exception {
        File f = write(pem("RSA PRIVATE KEY", new byte[] {1, 2, 3}));
        try {
            PemPrivateKeyLoader.load(f.getPath(), null);
            fail("expected exception");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("openssl pkcs8 -topk8"));
        }
    }

    @Test
    public void missingFileIsReported() {
        try {
            PemPrivateKeyLoader.load(new File(tmp.getRoot(), "nope.pem").getPath(), null);
            fail("expected exception");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("nope.pem"));
        }
    }
}
