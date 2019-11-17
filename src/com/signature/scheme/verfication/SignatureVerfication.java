package com.signature.scheme.verfication;

import com.signature.scheme.PublicKey;
import com.signature.scheme.Signature;
import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Arrays;

public class SignatureVerfication {

    public static Boolean verifySignature(PublicKey publicKey, Signature signature, PseudorndFunction f, int l1L, int l2L, int l1U, int l2U, int wL, int wU, byte[] x, byte[] m, int heightL, int heightU) {

        //Checking if msgSignature match msg
        int l = l1U + l2U;
        int n = f.n;
        int wBytes = HelperFunctions.ceilLogTwo(wL);
        int actualMsgIndex = 0;
        int index = signature.index;
        byte[][] OTSpublicKey = new byte[n][l];
        byte[][] msgSignature = signature.msgSignature;
        int msgPartBaseW;
        int controlSum = 0;

        for (int i = 0; i < l1L; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(m, actualMsgIndex, actualMsgIndex + wBytes));
            controlSum += (wL - 1 - msgPartBaseW);
            actualMsgIndex += wBytes;
            OTSpublicKey[i] = f.composeFunction(x, msgSignature[i], wL - 1 - msgPartBaseW);
        }

        actualMsgIndex = 0;
        byte[] byteControlSum = HelperFunctions.intToByteArray(controlSum, l2L);
        for (int i = 0; i < l2L; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(byteControlSum, actualMsgIndex, actualMsgIndex + wBytes));
            actualMsgIndex += wBytes;
            OTSpublicKey[l1L + i] = f.composeFunction(x, msgSignature[l1L + i], wL - 1 - msgPartBaseW);
        }

        //Checking if publicKey belongs to Merkle Tree
        Node node = MTreeOperations.leafCalc(n, l, OTSpublicKey, publicKey.bitmaskLTree,signature.index);
        Node[] authL = signature.lowerAuthPath;
        byte[][] bitmask = publicKey.bitmaskMain;

        for (int i = 1; i <= heightL; i++) {
            if (Math.floor(index / Math.pow(2, i)) % 2 == 0) {
                node = MTreeOperations.computeParent(node, authL[i - 1], bitmask[i - 1]);
            } else {
                node = MTreeOperations.computeParent(authL[i - 1], node, bitmask[i - 1]);
            }
        }

        //Generating OTSpublicKey from upper tree
        l = l1U + l2U;
        wBytes = HelperFunctions.ceilLogTwo(wU);
        actualMsgIndex = 0;
        //index = signature.index;
        OTSpublicKey = new byte[n][l];
        byte[][] lowerTreeSignature = signature.lowerTreeSignature;
        controlSum = 0;

        for (int i = 0; i < l1U; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(m, actualMsgIndex, actualMsgIndex + wBytes));
            controlSum += (wU - 1 - msgPartBaseW);
            actualMsgIndex += wBytes;
            OTSpublicKey[i] = f.composeFunction(x, msgSignature[i], wU - 1 - msgPartBaseW);
        }

        actualMsgIndex = 0;
        byteControlSum = HelperFunctions.intToByteArray(controlSum, l2U);
        for (int i = 0; i < l2U; i++) {
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(byteControlSum, actualMsgIndex, actualMsgIndex + wBytes));
            actualMsgIndex += wBytes;
            OTSpublicKey[l1U + i] = f.composeFunction(x, msgSignature[l1U + i], wU - 1 - msgPartBaseW);
        }

        //Checking if publicKey belongs to Merkle Tree
        node = MTreeOperations.leafCalc(n, l, OTSpublicKey, publicKey.bitmaskLTree,signature.treeIndex);
        Node[] authU = signature.upperAuthPath;

        for (int i = 1; i <= heightU; i++) {
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
