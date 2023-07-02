package com.dsingley.jwt.curator;

import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.dsingley.jwt.core.JwtKeyRepository;
import com.dsingley.jwt.core.JwtManager;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;
import org.apache.curator.test.TestingServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

class CuratorJwtKeyRepositoryTest {
    static TestingServer testingServer;
    static CuratorFramework curatorFramework;
    static JwtManager jwtManager;

    @BeforeAll
    public static void setUp() throws Exception {
        testingServer = new TestingServer();

        curatorFramework = CuratorFrameworkFactory.newClient(testingServer.getConnectString(), new RetryNTimes(3, 300));
        curatorFramework.start();

        JwtKeyRepository jwtKeyRepository = CuratorJwtKeyRepository.builder()
                .curatorFramework(curatorFramework)
                .build();

        jwtManager = JwtManager.builder()
                .issuer(CuratorJwtKeyRepositoryTest.class.getSimpleName())
                .ttlSeconds(300L)
                .repository(jwtKeyRepository)
                .build();
    }

    @AfterAll
    public static void tearDown() throws Exception {
        curatorFramework.close();
        testingServer.stop();
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
