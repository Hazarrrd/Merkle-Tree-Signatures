package com.signature.scheme.keys;

import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.TreehashNext;
import com.signature.scheme.signing.Signature;

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
