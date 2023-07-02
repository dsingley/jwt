package com.dsingley.jwt.curator;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.dsingley.jwt.core.JwtKeyRepository;
import com.dsingley.jwt.core.JwtManager;
import lombok.extern.slf4j.Slf4j;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.ExponentialBackoffRetry;

@Slf4j
public class IntegrationTest {
    private static final String ZK_CONNECT_STRING = "ZK_CONNECT_STRING";
    private static final String DEFAULT_ZK_CONNECT_STRING = "localhost:2181";
    private static final String ZK_KEY_PATH = "ZK_KEY_PATH";
    private static final String TTL_SECONDS = "TTL_SECONDS";
    private static final long DEFAULT_TTL_SECONDS = 300;

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage:");
            System.err.println("  create <subject>");
            System.err.println("  verify <token>");
            System.exit(1);
        }

        String zkConnectString = System.getenv(ZK_CONNECT_STRING);
        if (zkConnectString == null || zkConnectString.trim().length() == 0) {
            zkConnectString = DEFAULT_ZK_CONNECT_STRING;
        }
        log.debug("zkConnectString: {}", zkConnectString);

        String zkKeyPath = System.getenv(ZK_KEY_PATH);
        log.debug("zkKeyPath: {}", zkKeyPath);

        String ttlSecondsString = System.getenv(TTL_SECONDS);
        long ttlSeconds = ttlSecondsString != null ? Long.parseLong(ttlSecondsString) : DEFAULT_TTL_SECONDS;
        log.debug("ttlSeconds: {}", ttlSeconds);

        CuratorFramework curatorFramework = CuratorFrameworkFactory.newClient(zkConnectString, new ExponentialBackoffRetry(100, 10, 10_000));
        curatorFramework.start();

        JwtKeyRepository jwtKeyRepository = CuratorJwtKeyRepository.builder()
                .curatorFramework(curatorFramework)
                .keyPath(zkKeyPath)
                .build();

        JwtManager jwtManager = JwtManager.builder()
                .issuer(IntegrationTest.class.getSimpleName())
                .ttlSeconds(ttlSeconds)
                .repository(jwtKeyRepository)
                .build();

        switch (args[0]) {
            case "create":
                System.out.println(jwtManager.create(args[1], null));
                break;
            case "verify":
                DecodedJWT decodedJWT = jwtManager.verify(args[1]);
                decodedJWT.getClaims().forEach((k, v) -> System.out.printf("%s: %s%n", k, v));
                break;
            default:
                System.err.println("operation must be one of: create, verify");
                System.exit(2);
        }

        curatorFramework.close();
    }
}
