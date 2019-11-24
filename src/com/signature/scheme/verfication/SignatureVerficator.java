package com.signature.scheme.verfication;

import com.signature.scheme.*;
import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.awt.font.FontRenderContext;
import java.util.ArrayList;
import java.util.Arrays;

public class SignatureVerficator {

    public PublicKey publicKey;
    public ParametersBase params;

    public SignatureVerficator(PublicKey publicKey, ParametersBase params) {
        this.publicKey = publicKey;
        this.params = params;
    }

    public Boolean verifySignature(Signature signature, String msg) {

        HashFunction.setFunction(params.hashFunctionKey,params.n);

        byte [] msgDigest = HelperFunctions.messageDigestSHA3_256(msg);
        byte[][] bitmask = publicKey.bitmaskMain;
        int n = params.n;
        byte[] x = params.X;

        //setting params for lower tree
        int ll1 =params.ll1;
        int ll2 = params.ll2;
        int lL = params.lL;
        int wL = params.wL;
        int lowerH = signature.lowerAuthPath.length;

        //Computing lowerTree root
        byte [][] OTSpublicKey = WOTSkeyGenerator.computeOTSPublicKey(msgDigest, ll1, ll2, wL, x, signature.msgSignature);
        Node node = MTreeOperations.leafCalc(n, lL, OTSpublicKey, publicKey.bitmaskLTree,signature.index);
        node = MTreeOperations.computeRoot(lowerH, signature.index, node, signature.lowerAuthPath, bitmask);

        //setting params for upper trees
        int lu1 =params.lu1;
        int lu2 = params.lu2;
        int lU = params.lU;
        int wU = params.wU;
        int upperH = params.upperH;

        //Computing root of upper tree
        OTSpublicKey = WOTSkeyGenerator.computeOTSPublicKey(node.value, lu1, lu2, wU, x, signature.lowerTreeSignature);
        node = MTreeOperations.leafCalc(n, lU, OTSpublicKey, publicKey.bitmaskLTree, signature.treeIndex);
        node = MTreeOperations.computeRoot(upperH, signature.treeIndex, node, signature.upperAuthPath, bitmask);

        //Computing root of upper trees from previous structures if these were created
        ArrayList<StructureSignature> signaturesList = signature.structureSignatures;
        for (int i = signaturesList.size()-1;i>=0;i--) {
            StructureSignature temp = signaturesList.get(i);
            OTSpublicKey = WOTSkeyGenerator.computeOTSPublicKey(node.value, lu1, lu2, wU, x, temp.nextStructSignature);
            node = MTreeOperations.leafCalc(n, lU, OTSpublicKey, publicKey.bitmaskLTree, params.upperSize-1);
            node = MTreeOperations.computeRoot(upperH, params.upperSize-1, node, temp.oldStructAuthPath, bitmask);
        }

        //Checking if publicKey belongs to Merkle Tree
        if (Arrays.equals(node.value,publicKey.upperRoot)) {
            return true;
        } else {
            System.out.println("Root doesnt match");
            return false;
        }


    }


}
