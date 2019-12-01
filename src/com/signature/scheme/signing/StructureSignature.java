package com.signature.scheme.signing;

import com.signature.scheme.merkleTree.Node;

import java.io.Serializable;

public class StructureSignature implements Serializable {

    public Node[] oldStructAuthPath;
    public byte[][] nextStructSignature;

    public StructureSignature(Node[] authPath, byte[][] signature) {
        this.oldStructAuthPath = authPath;
        this.nextStructSignature = signature;
    }
}
