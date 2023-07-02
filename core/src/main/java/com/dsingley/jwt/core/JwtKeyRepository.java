package com.dsingley.jwt.core;

public interface JwtKeyRepository {

    void put(JwtPublicKey jwtPublicKey);

    JwtPublicKey get(String keyId);
}
