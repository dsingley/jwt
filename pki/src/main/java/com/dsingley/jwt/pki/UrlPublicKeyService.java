package com.dsingley.jwt.pki;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.time.Duration;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/**
 * An UrlPublicKeyService is a {@link PublicKeyService} implementation
 * that retries and caches the public keys of the servers specified
 * by <code>https://</code> URL <code>kid</code> values.
 */
@Slf4j
public class UrlPublicKeyService implements PublicKeyService {
    private static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(60);

    private final SSLSocketFactory sslSocketFactory;
    private final LoadingCache<URL, PublicKey> cache;

    @Builder
    public UrlPublicKeyService(
            SSLSocketFactory sslSocketFactory,
            Duration cacheTtl
    ) {
        this.sslSocketFactory = sslSocketFactory;
        cache = CacheBuilder.newBuilder()
                .expireAfterAccess(cacheTtl != null ? cacheTtl : DEFAULT_CACHE_TTL)
                .build(new CacheLoader<URL, PublicKey>() {
                    @Override
                    public @NonNull PublicKey load(@NonNull URL key) {
                        return loadPublicKey(key);
                    }
                });
    }

    /**
     * Get the public key of the server specified by the provided <code>kid</code> value.
     *
     * @param keyId <code>https://</code> URL <code>kid</code> value
     * @return the server's {@link PublicKey}
     */
    @Override
    public PublicKey getPublicKey(@NonNull String keyId) {
        URL url = getUrl(keyId);
        return cache.getUnchecked(url);
    }

    @SneakyThrows
    private URL getUrl(String keyId) {
        URL url = new URL(keyId);
        if (!"https".equals(url.getProtocol())) {
            throw new IllegalArgumentException("URL protocol is not https");
        }
        return url;
    }

    @SneakyThrows
    private PublicKey loadPublicKey(URL url) {
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        if (sslSocketFactory != null) {
            connection.setSSLSocketFactory(sslSocketFactory);
        }
        log.debug("connecting to {} to load public key...", url);
        connection.connect();
        Certificate serverCertificate = connection.getServerCertificates()[0];
        return serverCertificate.getPublicKey();
    }
}
