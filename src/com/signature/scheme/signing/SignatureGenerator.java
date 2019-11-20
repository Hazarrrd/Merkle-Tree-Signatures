package com.signature.scheme.signing;

import com.signature.scheme.*;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Arrays;

public class SignatureGenerator {

    KeysKeeper keysKeeper;

    public SignatureGenerator(KeysKeeper keysKeeper) {
        this.keysKeeper = keysKeeper;
    }

    private static byte[][] generateMsgSignature(byte[] seed, PseudorndFunction f, int l1, int l2, int w, byte[] x, byte[] msgDigest) {
        int l = l1 + l2;
        int n = f.n;
        int wBytes = HelperFunctions.ceilLogTwo(w);
        int actualMsgIndex = 0;
        int nextMsgIndex=wBytes;
        byte[] privatePart;
        int msgPartBaseW;
        int controlSum = 0;
        String msgBinaryString = HelperFunctions.byteArrayToBinaryString(msgDigest);
        while (msgBinaryString.length() % wBytes != 0){
            msgBinaryString += "0";
        }
        byte[][] signature = new byte[l][n];
        for (int i = 0; i < l1; i++) {
            privatePart = WOTSkeyGenerator.getPrivPart(l, f, i, seed);
            msgPartBaseW = Integer.parseInt(msgBinaryString.substring(actualMsgIndex, nextMsgIndex),2);
            controlSum += (w - 1 - msgPartBaseW);
            actualMsgIndex = nextMsgIndex;
            nextMsgIndex += wBytes;
            signature[i] = f.composeFunction(x, privatePart, msgPartBaseW);
        }
        actualMsgIndex = 0;
        nextMsgIndex = wBytes;
        String controlSumBinaryString = Integer.toBinaryString(controlSum);
        while (controlSumBinaryString.length() % wBytes != 0){
            controlSumBinaryString += "0";
        }
        for (int i = 0; i < l2; i++) {
            privatePart = WOTSkeyGenerator.getPrivPart(l, f, i + l1, seed);
            msgPartBaseW = Integer.parseInt(controlSumBinaryString.substring(actualMsgIndex, nextMsgIndex), 2);
            actualMsgIndex = nextMsgIndex;
            nextMsgIndex += wBytes;
            signature[l1 + i] = f.composeFunction(x, privatePart, msgPartBaseW);
        }

        return signature;
    }

    public static Signature signLowerTree(PrivateKey privateKey, int n, int l1, int l2, int w, byte[] x, byte[] msg) {
        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.upperGenState);
        Node[] authPath = (privateKey.upperPathComputation.auth).clone();
        int index = privateKey.upperPathComputation.leafIndex;
        privateKey.upperPathComputation.doAlgorithm();
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.upperGenState = fsGenerator.state;
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), l1, l2, w, x, msg);
        Signature lowerSignature = new Signature(authPath, msgSignature, index);
        privateKey.lowerSignature = lowerSignature;
        return lowerSignature;
    }

    public Signature signMessage(String msg) {
        HashFunction.setFunction(keysKeeper.params.hashFunctionKey,keysKeeper.params.n);
        byte [] msgDigest = HelperFunctions.messageDigestSHA3_256(msg);
        PrivateKey privateKey = this.keysKeeper.privateKey;
        ParametersBase params = this.keysKeeper.params;
        int n = params.n;

        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.lowerGenState);
        Node[] authPath = (privateKey.lowerPathComputation.auth).clone();
        int index = privateKey.lowerPathComputation.leafIndex;
        privateKey.lowerPathComputation.doAlgorithm();
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.lowerGenState = fsGenerator.state;
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), params.ll1, params.ll2, params.wL, params.X,msgDigest);

        return new Signature(authPath, msgSignature, index, privateKey.lowerSignature);
    }
}
