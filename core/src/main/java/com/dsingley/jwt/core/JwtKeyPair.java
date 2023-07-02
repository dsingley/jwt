package com.dsingley.jwt.core;

import lombok.Getter;
import lombok.ToString;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Getter
@ToString
public class JwtKeyPair  {
    private static final Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder();
    private static final String BEGIN_RSA_PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----";
    private static final String END_RSA_PUBLIC_KEY = "-----END RSA PUBLIC KEY-----";
    private static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    private final String keyId;
    private final OffsetDateTime expiresAt;
    @ToString.Exclude private final RSAPublicKey rsaPublicKey;
    @ToString.Exclude private final RSAPrivateKey rsaPrivateKey;

    public JwtKeyPair(long ttlSeconds, KeyPair keyPair) {
        keyId = UUID.randomUUID().toString().replace("-", "");
        expiresAt = OffsetDateTime.now().plus(ttlSeconds, ChronoUnit.SECONDS);
        rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    public JwtPublicKey toJwtPublicKey() {
        return JwtPublicKey.builder()
                .keyId(keyId)
                .expiresAt(expiresAt)
                .rsaPublicKey(rsaPublicKey)
                .build();
    }

    public static String encode(RSAPublicKey rsaPublicKey) {
        return String.format("%s%n%s%n%s", BEGIN_RSA_PUBLIC_KEY, MIME_ENCODER.encodeToString(rsaPublicKey.getEncoded()), END_RSA_PUBLIC_KEY);
    }

    public static String encode(RSAPrivateKey rsaPrivateKey) {
        return String.format("%s%n%s%n%s", BEGIN_RSA_PRIVATE_KEY, MIME_ENCODER.encodeToString(rsaPrivateKey.getEncoded()), END_RSA_PRIVATE_KEY);
    }
}
