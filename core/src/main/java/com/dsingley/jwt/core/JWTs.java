package com.dsingley.jwt.core;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import static com.auth0.jwt.HeaderParams.ALGORITHM;
import static com.auth0.jwt.HeaderParams.CONTENT_TYPE;
import static com.auth0.jwt.HeaderParams.KEY_ID;
import static com.auth0.jwt.HeaderParams.TYPE;
import static com.auth0.jwt.RegisteredClaims.*;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

@UtilityClass
public class JWTs {
    private static final List<String> HEADER_CLAIMS = Arrays.asList(ALGORITHM, TYPE, CONTENT_TYPE, KEY_ID);
    private static final List<String> REGISTERED_CLAIMS = Arrays.asList(ISSUER, JWT_ID, ISSUED_AT, NOT_BEFORE, EXPIRES_AT, AUDIENCE, SUBJECT);

    /**
     * Verify that the provided predicate returns true when evaluating the <code>kid</code> header
     * of the provided token.
     * <p>
     * If the predicate returns false an {@link InvalidClaimException} is thrown.
     *
     * @param decodedJWT            the token to verify
     * @param verificationPredicate the predicate to validate the Key ID
     * @throws InvalidClaimException if the predicate returns false
     */
    public static void verifyKeyId(@NonNull DecodedJWT decodedJWT, @NonNull Predicate<String> verificationPredicate) throws InvalidClaimException {
        String keyId = decodedJWT.getHeaderClaim(KEY_ID).asString();
        boolean isValid = verificationPredicate.test(keyId);
        if (!isValid) {
            throw new InvalidClaimException(String.format("The 'kid' value is not valid: %s", keyId));
        }
    }

    /**
     * Verify that the provided token has not expired, optionally allowing the specified leeway seconds.
     * <p>
     * If the token has expired a {@link TokenExpiredException} is thrown.
     *
     * @param decodedJWT    the token to verify
     * @param leewaySeconds the number of seconds to allow past the expiration time (optional)
     * @throws TokenExpiredException if the token has expired
     */
    public static void verifyExpiresAt(@NonNull DecodedJWT decodedJWT, @Nullable Long leewaySeconds) throws TokenExpiredException {
        Instant expiresAt = decodedJWT.getClaim(EXPIRES_AT).asInstant();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        boolean isValid = expiresAt == null || now.minusSeconds(leewaySeconds != null && leewaySeconds > 0 ? leewaySeconds : 0).isBefore(expiresAt);
        if (!isValid) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", expiresAt), expiresAt);
        }
    }

    public static List<String> listClaims(@NonNull DecodedJWT decodedJWT) {
        List<String> list = new ArrayList<>();
        list.addAll(listHeaders(decodedJWT));
        list.addAll(listPayload(decodedJWT));
        return list;
    }

    public static List<String> listHeaders(@NonNull DecodedJWT decodedJWT) {
        return HEADER_CLAIMS.stream()
                .collect(toMap(Function.identity(), decodedJWT::getHeaderClaim, (v1, v2) -> v1, LinkedHashMap::new))
                .entrySet().stream()
                .filter(entry -> !entry.getValue().isMissing())
                .map(entry -> String.format("%s: %s", entry.getKey(), entry.getValue()))
                .collect(toList());
    }

    public static List<String> listPayload(@NonNull DecodedJWT decodedJWT) {
        List<String> list = new ArrayList<>();
        REGISTERED_CLAIMS.forEach(name -> {
            Claim claim = decodedJWT.getClaim(name);
            if (!claim.isMissing()) {
                list.add(String.format("%s: %s", name, claim));
            }
        });
        decodedJWT.getClaims().keySet().stream()
                .sorted()
                .forEach(name -> {
                    if (!REGISTERED_CLAIMS.contains(name)) {
                        list.add(String.format("%s: %s", name, decodedJWT.getClaim(name)));
                    }
                });
        return list;
    }
}
