package com.dsingley.jwt.core;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * A supplier of {@link Algorithm} instances to be used in the Verification process of JSON Web Tokens.
 */
public interface VerificationAlgorithmSupplier {

    Algorithm getAlgorithm(DecodedJWT decodedJWT);
}
