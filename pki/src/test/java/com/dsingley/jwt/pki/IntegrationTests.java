package com.dsingley.jwt.pki;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.dsingley.jwt.core.JWTs;
import com.dsingley.jwt.core.JwtAlgorithm;
import com.dsingley.jwt.core.JwtManager;
import com.dsingley.jwt.core.SigningAlgorithmSupplier;
import com.dsingley.jwt.core.VerificationAlgorithmSupplier;
import com.dsingley.testpki.KeyType;
import com.dsingley.testpki.TestPKI;
import com.dsingley.testpki.TestPKICertificate;
import lombok.extern.slf4j.Slf4j;
import mockwebserver3.Dispatcher;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

@Slf4j
class IntegrationTests {
    static final JwtAlgorithm JWT_ALGORITHM = JwtAlgorithm.RS512;
    static MockWebServer mockWebServer;
    static String keyId;
    static JwtManager jwtManager;

    @BeforeAll
    static void setUp() throws IOException {
        TestPKI testPKI = new TestPKI(KeyType.RSA_2048, null);
        TestPKICertificate serverCertificate = testPKI.getOrCreateServerCertificate("jwt-issuer", Collections.singleton("localhost"));

        mockWebServer = new MockWebServer();
        mockWebServer.useHttps(serverCertificate.getSSLSocketFactory());
        mockWebServer.setDispatcher(new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest recordedRequest) throws InterruptedException {
                return new MockResponse.Builder()
                        .code(200)
                        .body(serverCertificate.getPublicKeyFingerprintSHA256())
                        .build();
            }
        });
        mockWebServer.start();

        keyId = String.format("%s#%s", mockWebServer.url("/"), serverCertificate.getPublicKeyFingerprintSHA256());
        SigningAlgorithmSupplier signingAlgorithmSupplier = new KeyPairSigningAlgorithmSupplier(JWT_ALGORITHM, serverCertificate.getKeyPair(), keyId);
        log.info("certificate for {}:\n{}", mockWebServer.url("/"), serverCertificate.getCertPem());

        PublicKeyService publicKeyService = UrlPublicKeyService.builder()
                .sslSocketFactory(serverCertificate.getSSLSocketFactory())
                .build();
        VerificationAlgorithmSupplier verificationAlgorithmSupplier = KeyIdVerificationAlgorithmSupplier.builder()
                .publicKeyService(publicKeyService)
                .build();

        jwtManager = JwtManager.builder()
                .issuer(IntegrationTests.class.getSimpleName())
                .ttlSeconds(30L)
                .signingAlgorithmSupplier(signingAlgorithmSupplier)
                .verificationAlgorithmSupplier(verificationAlgorithmSupplier)
                .keyIdPredicate(kid -> kid.startsWith(mockWebServer.url("/").toString()))
                .build();
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (mockWebServer != null) {
            mockWebServer.close();
        }
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
}
