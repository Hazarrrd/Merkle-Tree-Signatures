package com.signature.scheme;

import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;

public class PrivateKey {

    public byte[] lowerGenState;
    public byte[] nextGenState;
    public byte[] upperGenState;
    public PathComputation upperPathState;
    public PathComputation lowerPathState;
    public PathComputation nextPathState;
    public Signature lowerSignature;
    public Treehash nextThreehash;

}
