package com.dsingley.jwt.pki;

import com.auth0.jwt.algorithms.Algorithm;
import com.dsingley.jwt.core.JwtAlgorithm;
import com.dsingley.jwt.core.SigningAlgorithmSupplier;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;

/**
 * A KeyPairSigningAlgorithmSupplier is a {@link SigningAlgorithmSupplier} implementation
 * that constructs an {@link Algorithm} instance specified by the configured
 * {@link JwtAlgorithm}, {@link KeyPair}, and key id.
 * <p>
 * A KeyPairSigningAlgorithmSupplier instance will always return the same Algorithm instance.
 */
@Getter
@Slf4j
public class KeyPairSigningAlgorithmSupplier implements SigningAlgorithmSupplier {
    private final Algorithm algorithm;

    public KeyPairSigningAlgorithmSupplier(
            @NonNull String hashSize,
            @NonNull KeyPair keyPair,
            String keyId
    ) {
        this(JwtAlgorithm.compatibleWithKeyPairAndHashSize(keyPair, hashSize), keyPair, keyId);
    }

    public KeyPairSigningAlgorithmSupplier(
            @NonNull JwtAlgorithm jwtAlgorithm,
            @NonNull KeyPair keyPair,
            String keyId
    ) {
        algorithm = jwtAlgorithm.getSigningAlgorithm(keyPair, keyId);
        log.info("created {} signing algorithm with kid: {}", algorithm.getName(), algorithm.getSigningKeyId());
    }
}
