package com.dsingley.jwt.pki;

import java.security.PublicKey;

public interface PublicKeyService {

    PublicKey getPublicKey(String keyId);
}
