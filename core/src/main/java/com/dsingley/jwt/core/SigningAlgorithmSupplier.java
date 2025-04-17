package com.dsingley.jwt.core;

import com.auth0.jwt.algorithms.Algorithm;

/**
 * A supplier of {@link Algorithm} instances to be used in the Signing process of JSON Web Tokens.
 */
public interface SigningAlgorithmSupplier {

    Algorithm getAlgorithm();
}
