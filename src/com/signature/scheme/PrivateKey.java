package com.signature.scheme;

import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;

public class PrivateKey {

    public byte[] lowerGenState;
    public byte[] nextGenState;
    public byte[] upperGenState;
    public PathComputation upperPathComputation;
    public PathComputation lowerPathComputation;
    public PathComputation nextPathComputation;
    public Signature lowerSignature;
    public Treehash nextThreehash;

}
