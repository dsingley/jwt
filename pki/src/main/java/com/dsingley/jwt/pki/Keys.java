package com.dsingley.jwt.pki;

import com.google.common.annotations.VisibleForTesting;
import lombok.Getter;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

@UtilityClass
public class Keys {
    private static final Pattern KEYSTORE_TYPE_PATTERN = Pattern.compile(".*(?<extension>\\.(?:jks|p12|pkcs12))$");

    /**
     * Load a {@link KeyStore} from the specified file path, using the specified password if provided.
     *
     * @param keystorePath     the file path of the KeyStore to be loaded
     * @param keystorePassword the password to access the KeyStore (optional)
     * @return the loaded KeyStore instance
     */
    @SneakyThrows
    public static KeyStore loadKeyStore(
            @NonNull String keystorePath,
            String keystorePassword
    ) {
        KeyStore keyStore = getKeystoreInstance(keystorePath);
        try (InputStream inputStream = Files.newInputStream(Paths.get(keystorePath))) {
            keyStore.load(inputStream, keystorePassword != null ? keystorePassword.toCharArray() : null);
        }
        return keyStore;
    }

    /**
     * Retrieve a {@link KeyPair} consisting of the public and private keys from the provided {@link KeyStore}.
     * <p>
     * If an alias is not specified, a KeyPair including the first private key entry will be returned.
     *
     * @param keyStore    the KeyStore instance from which to retrieve the key pair
     * @param keyPassword the password to access the private key corresponding to the alias
     * @param alias       the alias identifying the private key entry within the KeyStore (optional)
     * @return the KeyPair containing the public and private keys
     * @throws IllegalArgumentException if the alias is not found or does not correspond to a private key entry
     */
    @SneakyThrows
    public static KeyPair getKeyPair(
            @NonNull KeyStore keyStore,
            @NonNull String keyPassword,
            String alias
    ) {
        if (alias == null) {
            alias = stream(keyStore.aliases())
                    .filter(a -> {
                        try {
                            return keyStore.isKeyEntry(a);
                        } catch (KeyStoreException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("no private key entry found in keystore"));
        } else {
            if (!keyStore.containsAlias(alias)) {
                throw new IllegalArgumentException(String.format("alias not found in keystore: '%s'", alias));
            }
            if (!keyStore.isKeyEntry(alias)) {
                throw new IllegalArgumentException(String.format("alias '%s' is not a private key entry", alias));
            }
        }
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Compute the SHA-256 fingerprint of the public key component of the provided {@link KeyPair}.
     *
     * @param keyPair the KeyPair containing a public key
     * @return a lowercase hexadecimal string representing the SHA-256 fingerprint of the public key
     */
    @SneakyThrows
    public static String computePublicKeyFingerprintSHA256(
            @NonNull KeyPair keyPair
    ) {
        byte[] encoded = keyPair.getPublic().getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(encoded);
        StringBuilder sb = new StringBuilder();
        for (byte b : hashed) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString().toLowerCase();
    }

    /**
     * Create an {@link SSLSocketFactory} using the provided key store and trust store.
     *
     * @param keyStore         the {@link KeyStore} containing a certificate and private key for client authentication
     * @param keystorePassword the password used to access the KeyStore
     * @param trustStore       the {@link KeyStore} containing trusted certificates for verifying server identity
     * @return the configured SSLSocketFactory for secure socket communication
     */
    public static SSLSocketFactory createSSLSocketFactory(
            @NonNull KeyStore keyStore,
            @NonNull String keystorePassword,
            @NonNull KeyStore trustStore
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
    public static SSLSocketFactory createSSLSocketFactory(
            @NonNull KeyStore keyStore,
            @NonNull String keystorePassword,
            @NonNull KeyStore trustStore,
            @NonNull SecureSocketProtocol secureSocketProtocol
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

    private static <T> Stream<T> stream(Enumeration<T> enumeration) {
        return StreamSupport.stream(
                Spliterators.spliteratorUnknownSize(
                        new Iterator<T>() {
                            @Override
                            public boolean hasNext() {
                                return enumeration.hasMoreElements();
                            }
                            @Override
                            public T next() {
                                return enumeration.nextElement();
                            }
                        },
                        Spliterator.ORDERED
                ),
                false
        );
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
