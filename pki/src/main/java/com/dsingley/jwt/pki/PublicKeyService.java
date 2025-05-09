package com.dsingley.jwt.pki;

import java.security.PublicKey;

/**
 * A service that returns {@link PublicKey} values for given {@code kid} values.
 * <p>
 * Used by {@link KeyIdVerificationAlgorithmSupplier} instances.
 */
public interface PublicKeyService {

    PublicKey getPublicKey(String keyId);
}
