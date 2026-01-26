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
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

/**
 * The VerifyOnlyJwtManager class provides a method for verifying JSON Web Tokens (JWTs).
 * <p>
 * Tokens are verified using an {@link Algorithm} provided by the configured {@link VerificationAlgorithmSupplier}
 * and optionally allowing for clock skew if leeway seconds are configured.
 * <p>
 * Additional token verification predicates can be configured for the Key ID header and payload claims.
 *
 * @see JwtManager
 */
@Slf4j
@SuperBuilder
public class VerifyOnlyJwtManager {
    private static final JWT JWT_INSTANCE = new JWT();

    @NonNull private final VerificationAlgorithmSupplier verificationAlgorithmSupplier;
    @Builder.Default private final long leewaySeconds = 0;
    private final Predicate<String> keyIdPredicate;
    @Singular private final Map<String, BiPredicate<Claim, DecodedJWT>> payloadPredicates;

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
