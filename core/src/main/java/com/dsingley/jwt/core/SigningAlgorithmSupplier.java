package com.dsingley.jwt.core;

import com.auth0.jwt.algorithms.Algorithm;

public interface SigningAlgorithmSupplier {

    Algorithm getAlgorithm();
}
