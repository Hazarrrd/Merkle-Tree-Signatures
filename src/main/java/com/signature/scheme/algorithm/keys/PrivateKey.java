package com.signature.scheme.algorithm.keys;

import com.signature.scheme.algorithm.merkleTree.PathComputation;
import com.signature.scheme.algorithm.merkleTree.TreehashNext;
import com.signature.scheme.algorithm.signing.Signature;

/**
 * Represents private key of the scheme
 */
public class PrivateKey {

    public byte[] lowerGenState;
    public byte[] nextGenState;
    public byte[] upperGenState;
    public PathComputation upperPathComputation;
    public PathComputation lowerPathComputation;
    public Signature lowerSignature;
    public TreehashNext nextThreehash;

}
