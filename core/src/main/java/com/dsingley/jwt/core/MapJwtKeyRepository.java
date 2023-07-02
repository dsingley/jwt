package com.dsingley.jwt.core;

import java.util.HashMap;
import java.util.Map;

public class MapJwtKeyRepository implements JwtKeyRepository {
    private final Map<String, JwtPublicKey> map = new HashMap<>();

    @Override
    public void put(JwtPublicKey jwtPublicKey) {
        map.put(jwtPublicKey.getKeyId(), jwtPublicKey);
    }

    @Override
    public JwtPublicKey get(String keyId) {
        return map.get(keyId);
    }
}
