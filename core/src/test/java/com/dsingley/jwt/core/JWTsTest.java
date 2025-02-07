package com.dsingley.jwt.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class JWTsTest {

    @Nested
    class VerifyExpiresAt {

        @Test
        void shouldNot_throwException_when_noExpirationClaim() {
            String jwt = JWT.create()
                    .sign(Algorithm.none());
            DecodedJWT decodedJWT = JWT.decode(jwt);

            assertThatNoException().isThrownBy(() ->
                    JWTs.verifyExpiresAt(decodedJWT, null)
            );
        }

        @Test
        void shouldNot_throwException_when_notExpired() {
            String jwt = JWT.create()
                    .withExpiresAt(Instant.now().plusSeconds(10))
                    .sign(Algorithm.none());
            DecodedJWT decodedJWT = JWT.decode(jwt);

            assertThatNoException().isThrownBy(() ->
                    JWTs.verifyExpiresAt(decodedJWT, null)
            );
        }

        @Test
        void shouldNot_throwException_when_expiredWithinLeewaySeconds() {
            String jwt = JWT.create()
                    .withExpiresAt(Instant.now().minusSeconds(5))
                    .sign(Algorithm.none());
            DecodedJWT decodedJWT = JWT.decode(jwt);

            assertThatNoException().isThrownBy(() ->
                    JWTs.verifyExpiresAt(decodedJWT, 10L)
            );
        }

        @Test
        void should_throwException_when_expired() {
            String jwt = JWT.create()
                    .withExpiresAt(Instant.now().minusSeconds(10))
                    .sign(Algorithm.none());
            DecodedJWT decodedJWT = JWT.decode(jwt);

            assertThatExceptionOfType(TokenExpiredException.class).isThrownBy(() ->
                    JWTs.verifyExpiresAt(decodedJWT, null)
            ).withMessageContaining("has expired");
        }

        @Test
        void should_throwException_when_expiredBeyondLeewaySeconds() {
            String jwt = JWT.create()
                    .withExpiresAt(Instant.now().minusSeconds(20))
                    .sign(Algorithm.none());
            DecodedJWT decodedJWT = JWT.decode(jwt);

            assertThatExceptionOfType(TokenExpiredException.class).isThrownBy(() ->
                    JWTs.verifyExpiresAt(decodedJWT, 10L)
            ).withMessageContaining("has expired");
        }
    }
}
