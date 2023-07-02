package com.dsingley.jwt.curator;

import com.dsingley.jwt.core.JwtKeyRepository;
import com.dsingley.jwt.core.JwtPublicKey;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.recipes.nodes.PersistentTtlNode;

import java.time.OffsetDateTime;
import java.util.concurrent.TimeUnit;

@Slf4j
public class CuratorJwtKeyRepository implements JwtKeyRepository {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final String DEFAULT_KEY_PATH = "/jwt/public-keys";

    private final CuratorFramework curatorFramework;
    private final String keyPath;

    @SneakyThrows
    @Builder
    public CuratorJwtKeyRepository(
            @NonNull CuratorFramework curatorFramework,
            String keyPath
    ) {
        this.curatorFramework = curatorFramework;
        this.keyPath = keyPath != null && keyPath.matches("/.+[^/]") ? keyPath : DEFAULT_KEY_PATH;
        this.curatorFramework
                .checkExists()
                .creatingParentsIfNeeded()
                .forPath(this.keyPath);
    }

    @SneakyThrows
    @Override
    public void put(JwtPublicKey jwtPublicKey) {
        byte[] bytes = OBJECT_MAPPER.writeValueAsBytes(jwtPublicKey);
        String path = keyPath + "/" + jwtPublicKey.getKeyId();
        OffsetDateTime expiresAt = jwtPublicKey.getExpiresAt();
        long ttlMs = expiresAt.toInstant().toEpochMilli() - OffsetDateTime.now().toInstant().toEpochMilli();
        log.debug("storing {} with {} ms TTL ...", path, ttlMs);
        PersistentTtlNode persistentTtlNode = new PersistentTtlNode(curatorFramework, path, ttlMs, bytes);
        persistentTtlNode.start();
        persistentTtlNode.waitForInitialCreate(1, TimeUnit.SECONDS);
    }

    @SneakyThrows
    @Override
    public JwtPublicKey get(String keyId) {
        String path = keyPath + "/" + keyId;
        log.debug("retrieving {} ...", path);
        byte[] bytes = curatorFramework.getData().forPath(path);
        return OBJECT_MAPPER.readValue(bytes, JwtPublicKey.class);
    }
}
