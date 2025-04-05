package com.dsingley.jwt.pki;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.dsingley.testpki.KeyType;
import com.dsingley.testpki.TestPKI;
import com.dsingley.testpki.TestPKICertificate;
import mockwebserver3.Dispatcher;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

class KeysTest {
    private static final TestPKI TEST_PKI = new TestPKI(KeyType.RSA_2048, null);

    @Nested
    class LoadKeyStore {

        @Test
        void should_loadKeyStore_from_testFile() throws Exception {
            TestPKICertificate serverCertificate = TEST_PKI.getOrCreateServerCertificate();
            String keystorePath = serverCertificate.getOrCreateKeystoreFile().getAbsolutePath();
            String keystorePassword = serverCertificate.getKeystorePassword();

            KeyStore keyStore = Keys.loadKeyStore(keystorePath, keystorePassword);

            assertThat(keyStore.getCertificate("server").getPublicKey())
                    .isEqualTo(serverCertificate.getKeyPair().getPublic());
        }
    }

    @Nested
    class GetKeyPair {

        @Test
        void should_getKeyPair_from_keyStore() {
            TestPKICertificate serverCertificate = TEST_PKI.getOrCreateServerCertificate();
            String keystorePath = serverCertificate.getOrCreateKeystoreFile().getAbsolutePath();
            String keystorePassword = serverCertificate.getKeystorePassword();
            KeyStore keyStore = Keys.loadKeyStore(keystorePath, keystorePassword);

            KeyPair keyPair = Keys.getKeyPair(keyStore, keystorePassword);

            assertAll(
                    () -> assertThat(keyPair.getPublic())
                            .isEqualTo(serverCertificate.getKeyPair().getPublic()),
                    () -> assertThat(keyPair.getPrivate())
                            .isEqualTo(serverCertificate.getKeyPair().getPrivate())
            );
        }
    }

    @Nested
    class CreateSSLSocketFactory {

        @Test
        void should_createSSLSocketFactory_from_testFiles() {
            TestPKICertificate clientCertificate = TEST_PKI.getOrCreateClientCertificate();
            String keystorePath = clientCertificate.getOrCreateKeystoreFile().getAbsolutePath();
            String keystorePassword = clientCertificate.getKeystorePassword();
            KeyStore keyStore = Keys.loadKeyStore(keystorePath, keystorePassword);
            String truststorePath = TEST_PKI.getOrCreateTruststoreFile().getAbsolutePath();
            String truststorePassword = TEST_PKI.getTruststorePassword();
            KeyStore trustStore = Keys.loadKeyStore(truststorePath, truststorePassword);

            SSLSocketFactory sslSocketFactory = Keys.createSSLSocketFactory(keyStore, keystorePassword, trustStore);

            assertThat(sslSocketFactory).isNotNull();
        }

        @Test
        void should_supportClientAuthentication() throws Exception {
            TestPKICertificate clientCertificate = TEST_PKI.getOrCreateClientCertificate();
            String keystorePath = clientCertificate.getOrCreateKeystoreFile().getAbsolutePath();
            String keystorePassword = clientCertificate.getKeystorePassword();
            KeyStore keyStore = Keys.loadKeyStore(keystorePath, keystorePassword);
            String truststorePath = TEST_PKI.getOrCreateTruststoreFile().getAbsolutePath();
            String truststorePassword = TEST_PKI.getTruststorePassword();
            KeyStore trustStore = Keys.loadKeyStore(truststorePath, truststorePassword);

            SSLSocketFactory sslSocketFactory = Keys.createSSLSocketFactory(keyStore, keystorePassword, trustStore);

            try (MockWebServer mockWebServer = new MockWebServer()) {
                mockWebServer.useHttps(TEST_PKI.getOrCreateServerCertificate().getSSLSocketFactory());
                mockWebServer.requireClientAuth();
                mockWebServer.setDispatcher(new Dispatcher() {
                    @NotNull
                    @Override
                    public MockResponse dispatch(@NotNull RecordedRequest recordedRequest) throws InterruptedException {
                        return new MockResponse.Builder()
                                .code(200)
                                .build();
                    }
                });

                URL url = new URL(mockWebServer.url("/").toString());
                HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                connection.setSSLSocketFactory(sslSocketFactory);
                connection.connect();

                assertThat(connection.getResponseCode()).isEqualTo(200);
            }
        }
    }

    @Nested
    class GetKeystoreInstance {

        @ParameterizedTest
        @CsvSource({"x.jks, JKS", "y.p12, PKCS12", "z.pkcs12, PKCS12"})
        void should_returnCorrectType_for_knownExtensions(String keystorePath, String expectedType) {
            KeyStore keystoreInstance = Keys.getKeystoreInstance(keystorePath);

            assertThat(keystoreInstance.getType()).isEqualTo(expectedType);
        }

        @Test
        void should_throwException_for_unknownExtension() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() ->
                            Keys.getKeystoreInstance("/path/with/unknown.extension")
                    );
        }
    }
}
