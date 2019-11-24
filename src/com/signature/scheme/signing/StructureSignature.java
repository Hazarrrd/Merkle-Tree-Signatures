package com.signature.scheme.signing;

import com.signature.scheme.merkleTree.Node;

public class StructureSignature {

    public Node[] oldStructAuthPath;
    public byte[][] nextStructSignature;

    public StructureSignature(Node[] authPath, byte[][] signature) {
        this.oldStructAuthPath = authPath;
        this.nextStructSignature = signature;
    }
}
