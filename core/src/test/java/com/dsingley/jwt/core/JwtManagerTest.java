package com.dsingley.jwt.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
class JwtManagerTest {
    static JwtManager jwtManager;

    @BeforeAll
    static void setup() {
        jwtManager = JwtManager.builder()
                .issuer(JwtManagerTest.class.getSimpleName())
                .ttlSeconds(60L)
                .repository(new MapJwtKeyRepository())
                .build();
    }

    @Test
    void test() {
        String subject = UUID.randomUUID().toString().replace("-", "");
        Map<String, Object> map = new HashMap<>();
        map.put("admin", true);
        map.put("groups", Arrays.asList("admins", "group1"));
        map.put("roles", Collections.singletonList("ROLE_1"));

        String token = jwtManager.create(subject, map);
        log.info("created token:\n{}", token);

        DecodedJWT decodedJWT = jwtManager.verify(token);
        assertThat(decodedJWT.getSubject())
                .isEqualTo(subject);
        decodedJWT.getClaims().forEach((k,v) -> log.info("{}: {}", k, v));
    }
}
