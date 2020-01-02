package com.signature.scheme.algorithm.signing;

import com.signature.scheme.algorithm.merkleTree.Node;

import java.io.Serializable;

/**
 * Class represents signatures of new structures, that are signed by older (used up) ones.
 */
public class StructureSignature implements Serializable {

    public Node[] oldStructAuthPath;
    public byte[][] nextStructSignature;

    public StructureSignature(Node[] authPath, byte[][] signature) {
        this.oldStructAuthPath = authPath;
        this.nextStructSignature = signature;
    }
}
