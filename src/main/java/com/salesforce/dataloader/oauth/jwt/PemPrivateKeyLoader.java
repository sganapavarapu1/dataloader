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

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/** Loads an RSA private key from a PKCS#8 PEM file, plain or password-encrypted, using the JDK only. */
public final class PemPrivateKeyLoader {
    private static final String PLAIN = "PRIVATE KEY";
    private static final String ENCRYPTED = "ENCRYPTED PRIVATE KEY";
    private static final String PKCS1 = "RSA PRIVATE KEY";

    private PemPrivateKeyLoader() {}

    public static PrivateKey load(String path, String password) {
        String pem;
        try {
            pem = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read the JWT private key file " + path + ": " + e.getMessage(), e);
        }
        if (pem.contains("BEGIN " + PKCS1)) {
            throw new IllegalArgumentException("The JWT private key file " + path + " is a PKCS#1 key. Convert it with: "
                    + "openssl pkcs8 -topk8 -nocrypt -in <old.pem> -out <new.pem>");
        }
        try {
            if (pem.contains("BEGIN " + ENCRYPTED)) {
                if (password == null || password.isEmpty()) {
                    throw new IllegalArgumentException("The JWT private key file " + path
                            + " is encrypted. Set sfdc.oauth.jwt.keypassword (encrypted with the Data Loader encrypt tool).");
                }
                return decrypt(body(pem, ENCRYPTED), password);
            }
            if (pem.contains("BEGIN " + PLAIN)) {
                return toKey(body(pem, PLAIN));
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            if (e instanceof IllegalArgumentException && e.getMessage() != null && e.getMessage().contains("sfdc.oauth.jwt")) {
                throw (IllegalArgumentException) e;
            }
            throw new IllegalArgumentException("Cannot parse the JWT private key file " + path
                    + " (wrong password or not a PKCS#8 RSA key?): " + e.getMessage(), e);
        }
        throw new IllegalArgumentException("The JWT private key file " + path + " is not a PEM PKCS#8 private key");
    }

    private static byte[] body(String pem, String label) {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int s = pem.indexOf(begin);
        int e = pem.indexOf(end);
        if (s < 0 || e < s) {
            throw new IllegalArgumentException("Malformed PEM block " + label);
        }
        return Base64.getMimeDecoder().decode(pem.substring(s + begin.length(), e));
    }

    private static PrivateKey toKey(byte[] der) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    // DER encodings of the PBKDF2 PRF OIDs (1.2.840.113549.2.x) and AES-CBC OIDs (2.16.840.1.101.3.4.1.x)
    private static final byte[][] PRF_OIDS = {oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08),
            oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09), oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A),
            oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B)};
    private static final String[] PRF_NAMES = {"HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"};
    private static final byte[][] AES_OIDS = {oid(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02),
            oid(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16), oid(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A)};
    private static final String[] AES_NAMES = {"AES_128", "AES_192", "AES_256"};

    private static byte[] oid(int... bytes) {
        byte[] b = new byte[bytes.length];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) bytes[i];
        }
        return b;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * EncryptedPrivateKeyInfo only reports "PBES2"; the JDK cipher name (e.g. PBEWithHmacSHA256AndAES_256) depends on
     * the PRF and cipher inside the parameters. openssl 1.x/LibreSSL default to HMAC-SHA1, openssl 3+ to HMAC-SHA256.
     */
    private static String pbes2AlgorithmName(EncryptedPrivateKeyInfo info) throws IOException, GeneralSecurityException {
        byte[] params = info.getAlgParameters().getEncoded();
        String prf = "HmacSHA1"; // PBKDF2 default when no PRF is present
        for (int i = 0; i < PRF_OIDS.length; i++) {
            if (contains(params, PRF_OIDS[i])) {
                prf = PRF_NAMES[i];
            }
        }
        for (int i = 0; i < AES_OIDS.length; i++) {
            if (contains(params, AES_OIDS[i])) {
                return "PBEWith" + prf + "And" + AES_NAMES[i];
            }
        }
        throw new GeneralSecurityException("unsupported PKCS#8 encryption scheme; use AES-CBC (openssl pkcs8 -topk8 -v2 aes-256-cbc)");
    }

    private static PrivateKey decrypt(byte[] der, String password) throws GeneralSecurityException {
        try {
            EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo(der);
            String algorithm = pbes2AlgorithmName(info);
            SecretKey secret = SecretKeyFactory.getInstance(algorithm)
                    .generateSecret(new PBEKeySpec(password.toCharArray()));
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secret, info.getAlgParameters());
            return toKey(info.getKeySpec(cipher).getEncoded());
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
