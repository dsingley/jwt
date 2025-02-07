package com.dsingley.jwt.core;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public interface VerificationAlgorithmSupplier {

    Algorithm getAlgorithm(DecodedJWT decodedJWT);
}
