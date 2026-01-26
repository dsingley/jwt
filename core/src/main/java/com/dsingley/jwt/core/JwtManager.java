package com.dsingley.jwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
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
 * <p>
 * Additional token verification predicates can be configured for the Key ID header and payload claims.
 *
 * @see VerifyOnlyJwtManager
 */
@Slf4j
@SuperBuilder
public class JwtManager extends VerifyOnlyJwtManager {
    @NonNull private final String issuer;
    @NonNull private final Long ttlSeconds;
    @NonNull private final SigningAlgorithmSupplier signingAlgorithmSupplier;

    /**
     * Create a signed token with the specified subject and claims payload.
     *
     * @param subject the subject of the token (required)
     * @param map     the data to include in the token as claims (optional)
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
}
