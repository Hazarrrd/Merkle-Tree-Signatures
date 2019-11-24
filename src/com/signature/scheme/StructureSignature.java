package com.signature.scheme;

import com.signature.scheme.merkleTree.Node;

import java.util.ArrayList;

public class StructureSignature {

    public Node[] oldStructAuthPath;
    public byte[][] nextStructSignature;

    public StructureSignature(Node[] authPath, byte[][] signature) {
        this.oldStructAuthPath = authPath;
        this.nextStructSignature = signature;
    }
}
