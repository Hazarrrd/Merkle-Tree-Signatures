package com.signature.scheme.signing;

import com.signature.scheme.merkleTree.Node;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Class represents digital signature
 */
public class Signature implements Serializable {
    public Node[] upperAuthPath;
    public byte[][] lowerTreeSignature;
    public Node[] lowerAuthPath;
    public byte[][] msgSignature;
    public int index;
    public int treeIndex;
    public ArrayList<StructureSignature> structureSignatures;

    public Signature(Node[] authPath, byte[][] msgSignature, int index) {
        this.upperAuthPath = authPath;
        this.lowerTreeSignature = msgSignature;
        this.treeIndex = index;
    }

    public Signature(Node[] authPath, byte[][] msgSignature, int index, Signature signature, ArrayList<StructureSignature> structureSignatures) {

        this.structureSignatures = structureSignatures;

        this.upperAuthPath = signature.upperAuthPath;
        this.lowerTreeSignature = signature.lowerTreeSignature;
        this.treeIndex = signature.treeIndex;

        this.lowerAuthPath = authPath;
        this.msgSignature = msgSignature;
        this.index = index;

    }
}
