package com.dsingley.jwt.hazelcast;

import com.dsingley.jwt.core.JwtKeyRepository;
import com.dsingley.jwt.core.JwtPublicKey;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.replicatedmap.ReplicatedMap;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.concurrent.TimeUnit;

@Slf4j
public class HazelcastKeyRepository implements JwtKeyRepository {
    private static final long DEFAULT_MOURNING_PERIOD_SECONDS = 60;

    private final ReplicatedMap<String, JwtPublicKey> replicatedMap;
    private final long mourningPeriodSeconds;

    @Builder
    public HazelcastKeyRepository(
            @NonNull HazelcastInstance hazelcastInstance,
            String mapName,
            Long mourningPeriodSeconds
    ) {
        if (mapName == null || mapName.trim().length() == 0) {
            mapName = HazelcastKeyRepository.class.getName();
        }
        replicatedMap = hazelcastInstance.getReplicatedMap(mapName);
        this.mourningPeriodSeconds = mourningPeriodSeconds != null && mourningPeriodSeconds >= 0 ? mourningPeriodSeconds : DEFAULT_MOURNING_PERIOD_SECONDS;
    }

    @Override
    public void put(JwtPublicKey jwtPublicKey) {
        long ttlMs = Math.max(Duration.between(OffsetDateTime.now(), jwtPublicKey.getExpiresAt()).toMillis(), 0) + (mourningPeriodSeconds * 1000);
        log.debug("storing {}[{}] with {} ms TTL ...", replicatedMap.getName(), jwtPublicKey.getKeyId(), ttlMs);
        replicatedMap.put(jwtPublicKey.getKeyId(), jwtPublicKey, ttlMs, TimeUnit.MILLISECONDS);
    }

    @Override
    public JwtPublicKey get(String keyId) {
        log.debug("retrieving {}[{}] ... ", replicatedMap.getName(), keyId);
        return replicatedMap.get(keyId);
    }
}
