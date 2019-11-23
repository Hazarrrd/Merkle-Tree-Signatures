package com.signature.scheme.signing;

import com.signature.scheme.*;
import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Arrays;
import java.util.Stack;

import static com.signature.scheme.tools.HelperFunctions.fillBytesRandomly;


public class SignatureGenerator {

    private final int n;
    private final PrivateKey privateKey;
    KeysKeeper keysKeeper;
    ParametersBase params;

    public SignatureGenerator(KeysKeeper keysKeeper) {
        this.keysKeeper = keysKeeper;
        privateKey = this.keysKeeper.privateKey;
        params = this.keysKeeper.params;
        n = params.n;
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
        while (msgBinaryString.length() % wBytes != 0 && msgBinaryString.length() != l1*wBytes){
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
        while (controlSumBinaryString.length() % wBytes != 0 && controlSumBinaryString.length() != l2*wBytes){
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
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.upperGenState = fsGenerator.state;
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), l1, l2, w, x, msg);
        Signature lowerSignature = new Signature(authPath, msgSignature, index);
        privateKey.lowerSignature = lowerSignature;
        if(index < privateKey.upperPathComputation.leafNumber-1){
            privateKey.upperPathComputation.doAlgorithm();
        };
        return lowerSignature;
    }

    public Signature signMessage(String msg) {
        byte[] msgDigest = HelperFunctions.messageDigestSHA3_256(msg);
        HashFunction.setFunction(keysKeeper.params.hashFunctionKey,keysKeeper.params.n);

        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.lowerGenState);
        Node[] authPath = (privateKey.lowerPathComputation.auth).clone();
        int index = privateKey.lowerPathComputation.leafIndex;
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.lowerGenState = fsGenerator.state;

        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), params.ll1, params.ll2, params.wL, params.X,msgDigest);

        Signature signature = new Signature(authPath, msgSignature, index, privateKey.lowerSignature);

        for (int i = 0;i<params.treeGrowth;i++){
            privateKey.nextThreehash.calculateNextNodes();
        }



        if(index == params.nextSize-1){
            privateKey.lowerGenState = privateKey.nextGenState;
            privateKey.lowerPathComputation = new PathComputation(params.nextH,params.kL,params.n,params.lL,keysKeeper.publicKey,params.wL
                    ,privateKey.nextGenState,privateKey.nextThreehash.authNext,privateKey.nextThreehash.treeHashArrayNext,privateKey.nextThreehash.retainNext);
            byte[] initialState = new byte[n];
            fillBytesRandomly(initialState);
            privateKey.nextGenState = initialState;
            byte [] lowerRootValue = privateKey.nextThreehash.stack.pop().value;
            keysKeeper.publicKey.lowerRoot = lowerRootValue;
            SignatureGenerator.signLowerTree(privateKey, params.n, params.lu1, params.lu2, params.wU, keysKeeper.publicKey.X, lowerRootValue);
            privateKey.nextThreehash = new TreehashNext(new Stack<>(),params.nextH,params.bitmaskMain,params.bitmaskLTree,params.n,params.lL,params.X,params.wL,params.kL,privateKey.nextGenState);
            params.lowerH = params.nextH;
            params.nextH = params.lowerH * params.treeGrowth;
            params.nextSize = (int) Math.pow(2,params.nextH);
        } else {
            privateKey.lowerPathComputation.doAlgorithm();
        }

        return signature;
    }
}
