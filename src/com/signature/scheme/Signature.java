package com.signature.scheme;

import com.signature.scheme.merkleTree.Node;

public class Signature {
    public Node[] upperAuthPath;
    public byte[][] lowerTreeSignature;
    public Node[] lowerAuthPath;
    public byte[][] msgSignature;
    public int index;
    public int treeIndex;

    public Signature(Node[] authPath, byte[][] msgSignature, int index, Boolean signLowerTree) {
        if (signLowerTree) {
            this.upperAuthPath = authPath;
            this.lowerTreeSignature = msgSignature;
            this.treeIndex = index;
        } else {
            this.lowerAuthPath = authPath;
            this.msgSignature = msgSignature;
            this.index = index;
        }
    }
}
