package com.dsingley.jwt.core;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import static com.auth0.jwt.RegisteredClaims.SUBJECT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

@Slf4j
class JwtManagerTest {
    static final JwtAlgorithm JWT_ALGORITHM = JwtAlgorithm.RS384;
    static String keyId;
    static JwtManager jwtManager;

    @BeforeAll
    static void setUp() throws Exception {
        keyId = UUID.randomUUID().toString().replace("-", "");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        log.info("public key for {}:\n{}", keyId, encodeToPem(keyPair.getPublic()));

        Algorithm signingAlgorithm = JWT_ALGORITHM.getSigningAlgorithm(keyPair, keyId);
        Algorithm verificationAlgorithm = JWT_ALGORITHM.getVerificationAlgorithm(keyPair.getPublic());
        SigningAlgorithmSupplier signingAlgorithmSupplier = () -> signingAlgorithm;
        VerificationAlgorithmSupplier verificationAlgorithmSupplier = decodedJWT -> {
            if (keyId.equals(decodedJWT.getKeyId())) {
                return verificationAlgorithm;
            }
            throw new JWTVerificationException("unable to supply Algorithm for kid: " + decodedJWT.getKeyId());
        };

        jwtManager = JwtManager.builder()
                .issuer(JwtManagerTest.class.getSimpleName())
                .ttlSeconds(30L)
                .signingAlgorithmSupplier(signingAlgorithmSupplier)
                .verificationAlgorithmSupplier(verificationAlgorithmSupplier)
                .payloadPredicate(SUBJECT, (claim, decodedJWT) -> claim.asString().startsWith("test"))
                .build();
    }

    @Test
    void testHeader() {
        String token = jwtManager.create("testHeader", null);
        log.info("created token:\n{}", token);

        DecodedJWT decodedJWT = jwtManager.verify(token);
        log.info("verified token:\n{}", String.join("\n", JWTs.listClaims(decodedJWT)));
        assertAll(
                () -> assertThat(decodedJWT.getAlgorithm()).isEqualTo(JWT_ALGORITHM.name()),
                () -> assertThat(decodedJWT.getType()).isEqualTo("JWT"),
                () -> assertThat(decodedJWT.getKeyId()).isEqualTo(keyId)
        );
    }

    @Test
    void testWithMap() {
        Map<String, Object> map = new TreeMap<>();
        map.put("admin", true);
        map.put("groups", Arrays.asList("admins", "group1"));
        map.put("roles", Collections.singletonList("ROLE_1"));

        String token = jwtManager.create("testWithMap", map);
        log.info("created token:\n{}", token);

        DecodedJWT decodedJWT = jwtManager.verify(token);
        assertAll(
                () -> assertThat(decodedJWT.getId()).matches("[0-9a-f]{32}"),
                () -> assertThat(decodedJWT.getSubject()).isEqualTo("testWithMap"),
                () -> assertThat(decodedJWT.getClaim("admin").asBoolean()).isTrue(),
                () -> assertThat(decodedJWT.getClaim("groups").asList(String.class)).containsExactly("admins", "group1"),
                () -> assertThat(decodedJWT.getClaim("roles").asList(String.class)).containsExactly("ROLE_1")
        );
        log.info("verified token:\n{}", String.join("\n", JWTs.listClaims(decodedJWT)));
    }

    private static String encodeToPem(PublicKey publicKey) {
        String pem = "-----BEGIN PUBLIC KEY-----\n";
        pem += Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
        pem += "\n-----END PUBLIC KEY-----\n";
        return pem;
    }
}
