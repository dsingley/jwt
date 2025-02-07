package com.dsingley.jwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

/**
 * The JwtManager class provides methods for creating and verifying JSON Web Tokens (JWTs).
 * <p>
 * Created tokens include the configured issuer, expire in the configured number of seconds,
 * and are signed with an {@link Algorithm} provided by the configured {@link SigningAlgorithmSupplier}.
 * <p>
 * Tokens are verified using an {@link Algorithm} provided by the configured {@link VerificationAlgorithmSupplier}
 * and optionally allowing for clock skew if leeway seconds are configured.
 * <p>
 * Additional token verification predicates can be configured for the Key ID header and payload claims.
 */
@Slf4j
public class JwtManager {
    private static final JWT JWT_INSTANCE = new JWT();

    private final String issuer;
    private final long ttlSeconds;
    private final SigningAlgorithmSupplier signingAlgorithmSupplier;
    private final VerificationAlgorithmSupplier verificationAlgorithmSupplier;
    private final long leewaySeconds;
    private final Predicate<String> keyIdPredicate;
    private final Map<String, BiPredicate<Claim, DecodedJWT>> payloadPredicates;

    @Builder
    public JwtManager(
            @NonNull String issuer,
            @NonNull Long ttlSeconds,
            @NonNull SigningAlgorithmSupplier signingAlgorithmSupplier,
            @NonNull VerificationAlgorithmSupplier verificationAlgorithmSupplier,
            Long leewaySeconds,
            Predicate<String> keyIdPredicate,
            @Singular Map<String, BiPredicate<Claim, DecodedJWT>> payloadPredicates
    ) {
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
        this.signingAlgorithmSupplier = signingAlgorithmSupplier;
        this.verificationAlgorithmSupplier = verificationAlgorithmSupplier;
        this.leewaySeconds = leewaySeconds != null && leewaySeconds > 0 ? leewaySeconds : 0;
        this.keyIdPredicate = keyIdPredicate;
        this.payloadPredicates = payloadPredicates;
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
    public DecodedJWT verify(@NonNull String token) throws JWTVerificationException {
        DecodedJWT decodedJWT = JWT_INSTANCE.decodeJwt(token);
        log.info("decoded jti: {} for sub: {}", decodedJWT.getId(), decodedJWT.getSubject());
        JWTs.verifyExpiresAt(decodedJWT, leewaySeconds);
        if (keyIdPredicate != null) {
            JWTs.verifyKeyId(decodedJWT, keyIdPredicate);
        }
        Verification verification = JWT.require(verificationAlgorithmSupplier.getAlgorithm(decodedJWT))
                .acceptLeeway(leewaySeconds);
        payloadPredicates.forEach(verification::withClaim);
        verification.build().verify(decodedJWT);
        log.info("verified jti: {} for sub: {}", decodedJWT.getId(), decodedJWT.getSubject());
        return decodedJWT;
    }
}
