package com.dsingley.jwt.pki;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dsingley.jwt.core.JwtAlgorithm;
import com.dsingley.jwt.core.VerificationAlgorithmSupplier;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.time.Duration;

/**
 * A KeyIdVerificationAlgorithmSupplier is a {@link VerificationAlgorithmSupplier} implementation
 * that constructs and caches {@link Algorithm} instances as required using the configured
 * {@link PublicKeyService}.
 */
@Slf4j
public class KeyIdVerificationAlgorithmSupplier implements VerificationAlgorithmSupplier {
    private static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(60);

    private final PublicKeyService publicKeyService;
    private final LoadingCache<JwtAlgorithmAndKeyId, Algorithm> algorithmCache;

    @Builder
    public KeyIdVerificationAlgorithmSupplier(
            @NonNull PublicKeyService publicKeyService,
            Duration cacheTtl
    ) {
        this.publicKeyService = publicKeyService;
        algorithmCache = CacheBuilder.newBuilder()
                .expireAfterAccess(cacheTtl != null ? cacheTtl : DEFAULT_CACHE_TTL)
                .build(CacheLoader.from(this::loadAlgorithm));
    }

    @Override
    public Algorithm getAlgorithm(@NonNull DecodedJWT decodedJWT) {
        JwtAlgorithm jwtAlgorithm = JwtAlgorithm.valueOf(decodedJWT.getAlgorithm());
        String keyId = decodedJWT.getKeyId();
        return algorithmCache.getUnchecked(new JwtAlgorithmAndKeyId(jwtAlgorithm, keyId));
    }

    private Algorithm loadAlgorithm(JwtAlgorithmAndKeyId jwtAlgorithmAndKeyId) {
        JwtAlgorithm jwtAlgorithm = jwtAlgorithmAndKeyId.jwtAlgorithm;
        String keyId = jwtAlgorithmAndKeyId.keyId;
        PublicKey publicKey = publicKeyService.getPublicKey(keyId);
        if (!jwtAlgorithm.isCompatible(publicKey)) {
            throw new RuntimeException(String.format("public key for kid: %s is not compatible with JWT algorithm: %s", keyId, jwtAlgorithm));
        }
        return jwtAlgorithm.getVerificationAlgorithm(publicKey);
    }

    @AllArgsConstructor
    @EqualsAndHashCode
    private static class JwtAlgorithmAndKeyId {
        private final JwtAlgorithm jwtAlgorithm;
        private final String keyId;
    }
}
