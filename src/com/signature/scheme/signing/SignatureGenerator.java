package com.signature.scheme.signing;

import com.signature.scheme.PrivateKey;
import com.signature.scheme.Signature;
import com.signature.scheme.WOTSkeyGenerator;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Arrays;

public class SignatureGenerator {
    public static byte[][] generateMsgSignature(byte[] seed, PseudorndFunction f, int l1, int l2, int w, byte[] x, byte[] m) {
        int l = l1 + l2;
        int n = f.n;
        int wBytes = HelperFunctions.ceilLogTwo(w);
        int actualMsgIndex = 0;
        byte[] privatePart;
        byte[] publicPart;
        int msgPartBaseW;
        int controlSum = 0;
        byte[][] signature = new byte[n][l];
        for (int i = 0; i < l1; i++) {
            privatePart = WOTSkeyGenerator.getPrivPart(l, f, i, seed);
            publicPart = WOTSkeyGenerator.getPublicPart(x, w, f, privatePart);
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(m, actualMsgIndex, actualMsgIndex + wBytes));
            controlSum += (w - 1 - msgPartBaseW);
            actualMsgIndex += wBytes;
            signature[i] = f.composeFunction(x, privatePart, msgPartBaseW);
        }
        actualMsgIndex = 0;
        byte[] byteControlSum = HelperFunctions.intToByteArray(controlSum, l2);
        for (int i = 0; i < l2; i++) {
            privatePart = WOTSkeyGenerator.getPrivPart(l, f, i + l1, seed);
            publicPart = WOTSkeyGenerator.getPublicPart(x, w, f, privatePart);
            msgPartBaseW = HelperFunctions.fromByteArray(Arrays.copyOfRange(byteControlSum, actualMsgIndex, actualMsgIndex + wBytes));
            actualMsgIndex += wBytes;
            signature[l1 + i] = f.composeFunction(x, privatePart, msgPartBaseW);
        }

        return signature;
    }

    public static Signature signLowerTree(PrivateKey privateKey, int n, int l1, int l2, int w, byte[] x, byte[] m, int height) {
        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.upperGenState);
        Node[] authPath = privateKey.upperPathState.auth;
        int index = privateKey.upperPathState.leafIndex;
        privateKey.upperPathState.doAlgorithm();
        byte[] seed = fsGenerator.nextStateAndSeed();
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), l1, l2, w, x, m);
        Signature lowerSignature = new Signature(authPath, msgSignature, index, true);
        privateKey.lowerSignature = lowerSignature;
        return lowerSignature;
    }

    public static Signature signMessage(PrivateKey privateKey, int n, int l1, int l2, int w, byte[] x, byte[] m, int height) {
        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.lowerGenState);
        Node[] authPath = privateKey.lowerPathState.auth;
        int index = privateKey.lowerPathState.leafIndex;
        privateKey.lowerPathState.doAlgorithm();
        byte[] seed = fsGenerator.nextStateAndSeed();
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), l1, l2, w, x, m);
        return new Signature(authPath, msgSignature, index, false);
    }
}
