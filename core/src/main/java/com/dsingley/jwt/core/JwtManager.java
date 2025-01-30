package com.dsingley.jwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * The JwtManager class provides methods for creating and verifying JSON Web Tokens (JWTs).
 * <p>
 * Created tokens include the configured issuer, expire in the configured number of seconds,
 * and are signed with an {@link Algorithm} provided by the configured {@link SigningAlgorithmSupplier}.
 * <p>
 * Tokens are verified using an {@link Algorithm} provided by the configured {@link VerificationAlgorithmSupplier}
 * and optionally allowing for clock skew if leeway seconds are configured.
 */
@Slf4j
public class JwtManager {
    private static final JWT JWT_INSTANCE = new JWT();

    private final String issuer;
    private final long ttlSeconds;
    private final SigningAlgorithmSupplier signingAlgorithmSupplier;
    private final VerificationAlgorithmSupplier verificationAlgorithmSupplier;
    private final long leewaySeconds;

    @Builder
    public JwtManager(
            @NonNull String issuer,
            @NonNull Long ttlSeconds,
            @NonNull SigningAlgorithmSupplier signingAlgorithmSupplier,
            @NonNull VerificationAlgorithmSupplier verificationAlgorithmSupplier,
            Long leewaySeconds
    ) {
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
        this.signingAlgorithmSupplier = signingAlgorithmSupplier;
        this.verificationAlgorithmSupplier = verificationAlgorithmSupplier;
        this.leewaySeconds = leewaySeconds != null && leewaySeconds > 0 ? leewaySeconds : 0;
    }

    /**
     * Create a signed token with the specified subject and claims payload.
     *
     * @param subject the subject of the token (required)
     * @param map the data to include in the token as claims (optional)
     * @return the signed token
     */
    public String create(@NonNull String subject, Map<String, ?> map) {
        String jti = UUID.randomUUID().toString().replace("-", "");
        Instant now = Instant.now();
        String jwt = JWT.create()
                .withIssuer(issuer)
                .withJWTId(jti)
                .withIssuedAt(now)
                .withNotBefore(now)
                .withExpiresAt(now.plusSeconds(ttlSeconds))
                .withSubject(subject)
                .withPayload(map)
                .sign(signingAlgorithmSupplier.getAlgorithm());
        log.info("created jti: {} for sub: {}", jti, subject);
        return jwt;
    }

    /**
     * Decode and verify the specified token.
     *
     * @param token the token to verify (required)
     * @return the decoded token if it is valid
     * @throws JWTVerificationException if the token is invalid
     */
    public DecodedJWT verify(@NonNull String token) {
        DecodedJWT decodedJWT = JWT_INSTANCE.decodeJwt(token);
        log.info("decoded jti: {} for sub: {}", decodedJWT.getId(), decodedJWT.getSubject());
        JWTs.verifyExpiresAt(decodedJWT, leewaySeconds);
        JWTVerifier jwtVerifier = JWT.require(verificationAlgorithmSupplier.getAlgorithm(decodedJWT))
                .acceptLeeway(leewaySeconds)
                .build();
        jwtVerifier.verify(decodedJWT);
        log.info("verified jti: {} for sub: {}", decodedJWT.getId(), decodedJWT.getSubject());
        return decodedJWT;
    }
}
