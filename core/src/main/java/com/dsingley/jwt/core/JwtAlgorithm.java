package com.dsingley.jwt.core;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.NonNull;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public enum JwtAlgorithm {
    RS256("RS", "256", "RSA"),
    RS384("RS", "384", "RSA"),
    RS512("RS", "512", "RSA"),
    ES256("ES", "256", "EC"),
    ES384("ES", "384", "EC"),
    ES512("ES", "512", "EC");

    /**
     * Select a {@link JwtAlgorithm} compatible with the provided {@link KeyPair} and specified hash size.
     *
     * @param keyPair  the {@link KeyPair} that will be used with the returned {@link JwtAlgorithm}
     * @param hashSize the desired hash size ({@code "256"}, {@code "384"}, or {@code "512"})
     * @return the matching {@link JwtAlgorithm}
     * @throws IllegalArgumentException if no matching JwtAlgorithm is found
     */
    public static JwtAlgorithm compatibleWithKeyPairAndHashSize(@NonNull KeyPair keyPair, @NonNull String hashSize) {
        return Arrays.stream(JwtAlgorithm.values())
                .filter(algorithm -> algorithm.isCompatible(keyPair.getPublic()))
                .filter(algorithm -> algorithm.hashSize.equals(hashSize))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no JwtAlgorithm is compatible with the provided key pair and hash size"));
    }

    /**
     * Test if the specified public key is compatible with this JwtAlgorithm.
     *
     * @param publicKey a {@link PublicKey} to check
     * @return <code>true</code> if the public key is compatible
     */
    public boolean isCompatible(@NonNull PublicKey publicKey) {
        return keyAlgorithm.equals(publicKey.getAlgorithm());
    }

    /**
     * Construct an {@link Algorithm} suitable for signing tokens, using this JwtAlgorithm,
     * the specified key pair, and optional key id.
     * <p>
     * <b>Note:</b> The key pair must be {@link JwtAlgorithm#isCompatible compatible} with this JwtAlgorithm.
     *
     * @param keyPair the {@link KeyPair} to use
     * @param keyId   a value to include as the <code>kid</code> in signed tokens (optional)
     * @return a configured {@link Algorithm}
     */
    public Algorithm getSigningAlgorithm(@NonNull KeyPair keyPair, String keyId) {
        if (!isCompatible(keyPair.getPublic())) {
            throw new IllegalArgumentException("key pair is not compatible with JWT algorithm: " + this);
        }
        switch (signatureType) {
            case "RS":
                return newRSA(keyPair, keyId);
            case "ES":
                return newECDSA(keyPair, keyId);
            default:
                throw new IllegalArgumentException("unexpected signature type: " + signatureType);
        }
    }

    /**
     * Construct an {@link Algorithm} suitable for verifying tokens, using this JwtAlgorithm
     * and the specified public key.
     * <p>
     * <b>Note:</b> The key pair must be {@link JwtAlgorithm#isCompatible compatible} with this JwtAlgorithm.
     *
     * @param publicKey the {@link PublicKey} to use
     * @return a configured {@link Algorithm}
     */
    public Algorithm getVerificationAlgorithm(@NonNull PublicKey publicKey) {
        if (!isCompatible(publicKey)) {
            throw new IllegalArgumentException("public key is not compatible with JWT algorithm: " + this);
        }
        switch (signatureType) {
            case "RS":
                return newRSA(new KeyPair(publicKey, null), null);
            case "ES":
                return newECDSA(new KeyPair(publicKey, null), null);
            default:
                throw new IllegalArgumentException("unexpected signature type: " + signatureType);
        }
    }

    JwtAlgorithm(String signatureType, String hashSize, String keyAlgorithm) {
        this.signatureType = signatureType;
        this.hashSize = hashSize;
        this.keyAlgorithm = keyAlgorithm;
    }

    private final String signatureType;
    private final String hashSize;
    private final String keyAlgorithm;

    private Algorithm newRSA(KeyPair keyPair, String keyId) {
        RSAKeyProvider keyProvider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return (RSAPublicKey) keyPair.getPublic();
            }
            @Override
            public RSAPrivateKey getPrivateKey() {
                return (RSAPrivateKey) keyPair.getPrivate();
            }
            @Override
            public String getPrivateKeyId() {
                return keyId;
            }
        };
        switch (hashSize) {
            case "256":
                return Algorithm.RSA256(keyProvider);
            case "384":
                return Algorithm.RSA384(keyProvider);
            case "512":
                return Algorithm.RSA512(keyProvider);
            default:
                throw new IllegalArgumentException("unexpected hash size: " + hashSize);
        }
    }

    private Algorithm newECDSA(KeyPair keyPair, String keyId) {
        ECDSAKeyProvider keyProvider = new ECDSAKeyProvider() {
            @Override
            public ECPublicKey getPublicKeyById(String keyId) {
                return (ECPublicKey) keyPair.getPublic();
            }
            @Override
            public ECPrivateKey getPrivateKey() {
                return (ECPrivateKey) keyPair.getPrivate();
            }
            @Override
            public String getPrivateKeyId() {
                return keyId;
            }
        };
        switch (hashSize) {
            case "256":
                return Algorithm.ECDSA256(keyProvider);
            case "384":
                return Algorithm.ECDSA384(keyProvider);
            case "512":
                return Algorithm.ECDSA512(keyProvider);
            default:
                throw new IllegalArgumentException("unexpected hash size: " + hashSize);
        }
    }
}
