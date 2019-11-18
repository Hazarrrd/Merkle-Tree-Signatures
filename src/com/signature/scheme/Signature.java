package com.signature.scheme;

import com.signature.scheme.merkleTree.Node;

public class Signature {
    public Node[] upperAuthPath;
    public byte[][] lowerTreeSignature;
    public Node[] lowerAuthPath;
    public byte[][] msgSignature;
    public int index;
    public int treeIndex;

    public Signature(Node[] authPath, byte[][] msgSignature, int index) {
        this.upperAuthPath = authPath;
        this.lowerTreeSignature = msgSignature;
        this.treeIndex = index;
    }

    public Signature(Node[] authPath, byte[][] msgSignature, int index, Signature signature) {

        this.upperAuthPath = signature.upperAuthPath;
        this.lowerTreeSignature = signature.lowerTreeSignature;
        this.treeIndex = signature.treeIndex;
        this.lowerAuthPath = authPath;
        this.msgSignature = msgSignature;
        this.index = index;

    }
}
