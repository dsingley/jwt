package com.dsingley.jwt.pki;

import com.google.common.annotations.VisibleForTesting;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

@UtilityClass
public class Keys {
    private static final Pattern KEYSTORE_TYPE_PATTERN = Pattern.compile(".*(?<extension>\\.(?:jks|p12|pkcs12))$");

    /**
     * Load a {@link KeyStore} from the specified file path using the provided password.
     *
     * @param keystorePath     the file path of the KeyStore to be loaded
     * @param keystorePassword the password to access the KeyStore
     * @return the loaded KeyStore instance
     */
    @SneakyThrows
    public static KeyStore loadKeyStore(
            String keystorePath,
            String keystorePassword
    ) {
        KeyStore keyStore = getKeystoreInstance(keystorePath);
        try (InputStream inputStream = Files.newInputStream(Paths.get(keystorePath))) {
            keyStore.load(inputStream, keystorePassword.toCharArray());
        }
        return keyStore;
    }

    /**
     * Retrieve the first {@link KeyPair} consisting of public and private keys from the provided {@link KeyStore}.
     *
     * @param keyStore    the KeyStore instance from which to retrieve the key pair
     * @param keyPassword the password to access the private key
     * @return the KeyPair containing the public and private keys
     * @throws IllegalArgumentException if no private key entry is found in the KeyStore
     */
    @SneakyThrows
    public static KeyPair getKeyPair(
            KeyStore keyStore,
            String keyPassword
    ) {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return getKeyPair(keyStore, alias, keyPassword);
            }
        }
        throw new IllegalArgumentException("no private key entry found in keystore");
    }

    /**
     * Retrieve a {@link KeyPair} consisting of the public and private keys with the specified alias from the provided {@link KeyStore}.
     *
     * @param keyStore    the KeyStore instance from which to retrieve the key pair
     * @param alias       the alias identifying the private key entry within the KeyStore
     * @param keyPassword the password to access the private key corresponding to the alias
     * @return the KeyPair containing the public and private keys
     * @throws IllegalArgumentException if the alias does not correspond to a private key entry in the KeyStore
     */
    @SneakyThrows
    public static KeyPair getKeyPair(
            KeyStore keyStore,
            String alias,
            String keyPassword
    ) {
        if (!keyStore.isKeyEntry(alias)) {
            throw new IllegalArgumentException(String.format("alias '%s' is not a private key entry", alias));
        }
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Create an {@link SSLSocketFactory} using the provided key store and trust store.
     *
     * @param keyStore         the {@link KeyStore} containing a certificate and private key for client authentication
     * @param keystorePassword the password used to access the KeyStore
     * @param trustStore       the {@link KeyStore} containing trusted certificates for verifying server identity
     * @return the configured SSLSocketFactory for secure socket communication
     */
    public SSLSocketFactory createSSLSocketFactory(
            KeyStore keyStore,
            String keystorePassword,
            KeyStore trustStore
    ) {
        return createSSLSocketFactory(keyStore, keystorePassword, trustStore, SecureSocketProtocol.TLS_1_2);
    }

    /**
     * Create an {@link SSLSocketFactory} supporting the specified {@link SecureSocketProtocol} using the provided key store and trust store.
     *
     * @param keyStore             the {@link KeyStore} containing a certificate and private key for client authentication
     * @param keystorePassword     the password used to access the KeyStore
     * @param trustStore           the {@link KeyStore} containing trusted certificates for verifying server identity
     * @param secureSocketProtocol the desired SecureSocketProtocol
     * @return the configured SSLSocketFactory for secure socket communication
     */
    @SneakyThrows
    public SSLSocketFactory createSSLSocketFactory(
            KeyStore keyStore,
            String keystorePassword,
            KeyStore trustStore,
            SecureSocketProtocol secureSocketProtocol
    ) {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance(secureSocketProtocol.getValue());
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext.getSocketFactory();
    }

    @SneakyThrows
    @VisibleForTesting
    static KeyStore getKeystoreInstance(String keystorePath) {
        Matcher matcher = KEYSTORE_TYPE_PATTERN.matcher(keystorePath);
        if (matcher.matches()) {
            String extension = matcher.group("extension");
            switch (extension) {
                case ".jks":
                    return KeyStore.getInstance("JKS");
                case ".p12":
                case ".pkcs12":
                    return KeyStore.getInstance("PKCS12");
                default:
                    throw new IllegalArgumentException(String.format("unexpected extension: %s", extension));
            }
        }
        throw new IllegalArgumentException(String.format("unable to determine KeyStore type for: %s", keystorePath));
    }

    @Getter
    public enum SecureSocketProtocol {
        TLS_1_2("TLSv1.2"),
        TLS_1_3("TLSv1.3");

        SecureSocketProtocol(String value) {
            this.value = value;
        }

        private final String value;
    }
}
