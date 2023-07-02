package com.dsingley.jwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.RegisteredClaims;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.IncorrectClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.google.common.base.Suppliers;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

@Slf4j
public class JwtManager {
    private static final KeyPairGenerator KEY_PAIR_GENERATOR = newKeyPairGenerator();
    private static final JWT JWT_INSTANCE = new JWT();

    private final String issuer;
    private final long ttlSeconds;
    private final long leewaySeconds;
    private final Supplier<JwtKeyPair> supplier;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    @Builder
    public JwtManager(
            @NonNull String issuer,
            @NonNull Long ttlSeconds,
            @NonNull JwtKeyRepository repository,
            Long leewaySeconds
    ) {
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
        this.leewaySeconds = leewaySeconds != null && leewaySeconds > 0 ? leewaySeconds : 0;
        supplier = Suppliers.memoizeWithExpiration(() -> {
            JwtKeyPair jwtKeyPair = new JwtKeyPair(ttlSeconds, KEY_PAIR_GENERATOR.generateKeyPair());
            if (log.isTraceEnabled()) {
                log.info("generated kid: {}\n{}\n{}", jwtKeyPair.getKeyId(), JwtKeyPair.encode(jwtKeyPair.getRsaPublicKey()), JwtKeyPair.encode(jwtKeyPair.getRsaPrivateKey()));
            } else {
                log.info("generated kid: {}", jwtKeyPair.getKeyId());
            }
            repository.put(jwtKeyPair.toJwtPublicKey());
            return jwtKeyPair;
        }, ttlSeconds, TimeUnit.SECONDS);
        algorithm = Algorithm.RSA512(new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                JwtKeyPair jwtKeyPair = supplier.get();
                return jwtKeyPair.getKeyId().equals(keyId)
                        ? jwtKeyPair.getRsaPublicKey()
                        : repository.get(keyId).getRsaPublicKey();
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return supplier.get().getRsaPrivateKey();
            }

            @Override
            public String getPrivateKeyId() {
                return supplier.get().getKeyId();
            }
        });
        verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .acceptLeeway(this.leewaySeconds)
                .build();
    }

    public String create(String subject, Map<String, ?> map) {
        String jti = UUID.randomUUID().toString().replace("-", "");
        Instant now = Instant.now();
        String jwt = JWT.create()
                .withIssuer(issuer)
                .withJWTId(jti)
                .withIssuedAt(now)
                .withNotBefore(now)
                .withExpiresAt(now.plus(ttlSeconds, ChronoUnit.SECONDS))
                .withSubject(subject)
                .withPayload(map)
                .sign(algorithm);
        log.info("created jti: {} for sub: {}", jti, subject);
        return jwt;
    }

    public DecodedJWT verify(String token) {
        DecodedJWT decodedJWT = JWT_INSTANCE.decodeJwt(token);
        log.info("decoded jti: {} for sub: {}", decodedJWT.getId(), decodedJWT.getSubject());

        // check token expiration before requiring the public key for signature verification
        // because the public key may no longer be available
        Instant expiresAt = decodedJWT.getClaim(RegisteredClaims.EXPIRES_AT).asInstant();
        if (expiresAt != null && !Instant.now().minus(Duration.ofSeconds(leewaySeconds)).isBefore(expiresAt)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", expiresAt), expiresAt);
        }

        verifier.verify(decodedJWT);
        log.info("verified jti: {} for sub: {}", decodedJWT.getId(), decodedJWT.getSubject());
        return decodedJWT;
    }

    @SneakyThrows
    private static KeyPairGenerator newKeyPairGenerator() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator;
    }
}
