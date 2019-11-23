package com.signature.scheme;

import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;

import java.util.Stack;

public class PrivateKey {

    public byte[] lowerGenState;
    public byte[] nextGenState;
    public byte[] upperGenState;
    public PathComputation upperPathComputation;
    public PathComputation lowerPathComputation;
    public Signature lowerSignature;
    public TreehashNext nextThreehash;

}
