package com.dsingley.jwt.hazelcast;

import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.dsingley.jwt.core.JwtKeyRepository;
import com.dsingley.jwt.core.JwtManager;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

class HazelcastKeyRepositoryTest {
    static HazelcastInstance hazelcastInstance;
    static JwtManager jwtManager;

    @BeforeAll
    static void setup() {
        Config config = new Config();
        config.setProperty("hazelcast.logging.type", "slf4j");
        hazelcastInstance = Hazelcast.newHazelcastInstance(config);

        JwtKeyRepository jwtKeyRepository = HazelcastKeyRepository.builder()
                .hazelcastInstance(hazelcastInstance)
                .mourningPeriodSeconds(30L)
                .build();

        jwtManager = JwtManager.builder()
                .issuer(HazelcastKeyRepositoryTest.class.getSimpleName())
                .ttlSeconds(300L)
                .repository(jwtKeyRepository)
                .build();
    }

    @AfterAll
    static void tearDown() {
        hazelcastInstance.shutdown();
    }

    @Test
    void test() {
        String subject = UUID.randomUUID().toString().replace("-", "");

        String token = jwtManager.create(subject, null);

        DecodedJWT decodedJWT = jwtManager.verify(token);
        assertThat(decodedJWT.getSubject())
                .isEqualTo(subject);
    }
}
