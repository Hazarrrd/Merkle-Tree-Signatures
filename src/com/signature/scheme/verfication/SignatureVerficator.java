package com.signature.scheme.verfication;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.PublicKey;
import com.signature.scheme.Signature;
import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Arrays;

public class SignatureVerficator {

    PublicKey publicKey;

    public SignatureVerficator(PublicKey publicKey, ParametersBase params) {
        this.publicKey = publicKey;
        this.params = params;
    }

    ParametersBase params;

    public Boolean verifySignature(Signature signature, String msg) {

        byte [] msgDigest = HelperFunctions.messageDigestSHA3_256(msg);
        //Checking if msgSignature match msg
        int ll1 =params.ll1;
        int ll2 = params.ll2;
        int lL = params.lL;
        int n = params.n;
        int wL = params.wL;
        byte[] x = params.X;
        int lowerH = params.lowerH;

        int wBytes = HelperFunctions.ceilLogTwo(wL);
        int actualMsgIndex = 0;
        int index = signature.index;
        byte[][] OTSpublicKey = new byte[n][lL];
        byte[][] msgSignature = signature.msgSignature;
        int msgPartBaseW;
        int controlSum = 0;
        PseudorndFunction f = new PseudorndFunction(params.n);

        for (int i = 0; i < ll1; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(msgDigest, actualMsgIndex, actualMsgIndex + wBytes));
            controlSum += (wL - 1 - msgPartBaseW);
            actualMsgIndex += wBytes;
            OTSpublicKey[i] = f.composeFunction(x, msgSignature[i], wL - 1 - msgPartBaseW);
        }

        actualMsgIndex = 0;
        byte[] byteControlSum = HelperFunctions.intToByteArray(controlSum, ll2);
        for (int i = 0; i < ll2; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(byteControlSum, actualMsgIndex, actualMsgIndex + wBytes));
            actualMsgIndex += wBytes;
            OTSpublicKey[ll1 + i] = f.composeFunction(x, msgSignature[ll1 + i], wL - 1 - msgPartBaseW);
        }

        //Checking if publicKey belongs to Merkle Tree
        Node node = MTreeOperations.leafCalc(n, lL, OTSpublicKey, publicKey.bitmaskLTree,signature.index);
        Node[] authL = signature.lowerAuthPath;
        byte[][] bitmask = publicKey.bitmaskMain;

        for (int i = 1; i <= lowerH; i++) {
            if (Math.floor(index / Math.pow(2, i)) % 2 == 0) {
                node = MTreeOperations.computeParent(node, authL[i - 1], bitmask[i - 1]);
            } else {
                node = MTreeOperations.computeParent(authL[i - 1], node, bitmask[i - 1]);
            }
        }

        //Generating OTSpublicKey from upper tree
        int lu1 =params.lu1;
        int lu2 = params.lu2;
        int lU = params.lU;
        int wU = params.wU;
        int upperH = params.upperH;
        wBytes = HelperFunctions.ceilLogTwo(wU);
        actualMsgIndex = 0;
        //index = signature.index;
        OTSpublicKey = new byte[n][lU];
        byte[][] lowerTreeSignature = signature.lowerTreeSignature;
        controlSum = 0;

        for (int i = 0; i < lu1; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(msgDigest, actualMsgIndex, actualMsgIndex + wBytes));
            controlSum += (wU - 1 - msgPartBaseW);
            actualMsgIndex += wBytes;
            OTSpublicKey[i] = f.composeFunction(x, msgSignature[i], wU - 1 - msgPartBaseW);
        }

        actualMsgIndex = 0;
        byteControlSum = HelperFunctions.intToByteArray(controlSum, lu2);
        for (int i = 0; i < lu2; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(byteControlSum, actualMsgIndex, actualMsgIndex + wBytes));
            actualMsgIndex += wBytes;
            OTSpublicKey[lu1 + i] = f.composeFunction(x, msgSignature[lu1 + i], wU - 1 - msgPartBaseW);
        }

        //Checking if publicKey belongs to Merkle Tree
        node = MTreeOperations.leafCalc(n, lU, OTSpublicKey, publicKey.bitmaskLTree,signature.treeIndex);
        Node[] authU = signature.upperAuthPath;

        for (int i = 1; i <= upperH; i++) {
            if (Math.floor(index / Math.pow(2, i)) % 2 == 0) {
                node = MTreeOperations.computeParent(node, authU[i - 1], bitmask[i - 1]);
            } else {
                node = MTreeOperations.computeParent(authU[i - 1], node, bitmask[i - 1]);
            }
        }

        if (node.value == publicKey.upperRoot) {
            return true;
        } else {
            System.out.println("Root doesnt match");
            return false;
        }

    }

}
