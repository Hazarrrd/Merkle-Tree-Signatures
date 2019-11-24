package com.signature.scheme.signing;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.keys.KeysKeeper;
import com.signature.scheme.keys.PrivateKey;
import com.signature.scheme.keys.PublicKey;
import com.signature.scheme.keys.WOTSkeyGenerator;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.TreehashNext;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.ArrayList;
import java.util.Stack;

import static com.signature.scheme.tools.HelperFunctions.fillBytesRandomly;


public class SignatureGenerator {

    private final int n;
    private PrivateKey privateKey;
    KeysKeeper keysKeeper;
    ParametersBase params;
    ArrayList<StructureSignature> upperSignatures;

    public SignatureGenerator(KeysKeeper keysKeeper) {
        this.keysKeeper = keysKeeper;
        privateKey = this.keysKeeper.privateKey;
        params = this.keysKeeper.params;
        n = params.n;
        upperSignatures = new ArrayList<>();
    }

    private  void replaceStructure() {
        //Generating new structure and replacing actual
        PublicKey publicKey = keysKeeper.publicKey;
        params.setTreeSizees(params.initialLowerSize,params.treeGrowth,params.upperH);
        this.keysKeeper.generateKeys();
        //Signing new structure by old
        StructureSignature structureSignature = signNextStruct(privateKey, params.n, params.lu1, params.lu2, params.wU, publicKey.X, keysKeeper.publicKey.upperRoot);
        upperSignatures.add(structureSignature);
        privateKey = this.keysKeeper.privateKey;
    }

    private StructureSignature signNextStruct(PrivateKey privateKey, int n, int l1, int l2, int w, byte[] x, byte[] msg) {
        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.upperGenState);
        Node[] authPath = (privateKey.upperPathComputation.auth).clone();
        int index = privateKey.upperPathComputation.leafIndex;
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.upperGenState = fsGenerator.state;

        //make a signature of lower tree
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), l1, l2, w, x, msg);
        StructureSignature lowerSignature = new StructureSignature(authPath, msgSignature);
        return lowerSignature;

    }

    public static void signLowerTree(PrivateKey privateKey, int n, int l1, int l2, int w, byte[] x, byte[] msg) {
        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.upperGenState);
        Node[] authPath = (privateKey.upperPathComputation.auth).clone();
        int index = privateKey.upperPathComputation.leafIndex;
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.upperGenState = fsGenerator.state;

        //make a signature of lower tree
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), l1, l2, w, x, msg);
        Signature lowerSignature = new Signature(authPath, msgSignature, index);
        privateKey.lowerSignature = lowerSignature;
        privateKey.upperPathComputation.doAlgorithm();
    }

    public Signature signMessage(String msg) {
        byte[] msgDigest = HelperFunctions.messageDigestSHA3_256(msg);
        HashFunction.setFunction(keysKeeper.params.hashFunctionKey,keysKeeper.params.n);
        FSGenerator fsGenerator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), privateKey.lowerGenState);
        Node[] authPath = (privateKey.lowerPathComputation.auth).clone();
        int index = privateKey.lowerPathComputation.leafIndex;
        byte[] seed = fsGenerator.nextStateAndSeed();
        privateKey.lowerGenState = fsGenerator.state;

        //make the signature of msg
        byte[][] msgSignature = generateMsgSignature(seed, new PseudorndFunction(n), params.ll1, params.ll2, params.wL, params.X,msgDigest);
        Signature signature = new Signature(authPath, msgSignature, index, privateKey.lowerSignature, (ArrayList<StructureSignature>) upperSignatures.clone());

        // Prepere for the next signature
        if(index == params.lowerSize-1){
            if(signature.treeIndex != (params.upperSize-2)) {
                //Prepare next lower tree
                buildNextTree();
                replaceLowerWithNext(signature.treeIndex);
            }
            else{
                replaceStructure();
            }

        } else {
            //Prepare next lower tree
            buildNextTree();
            privateKey.lowerPathComputation.doAlgorithm();
        }

        return signature;
    }

    private void buildNextTree() {
        int nodesToCalculate = (int) Math.pow(2, params.treeGrowth);
        for (int i = 0; i < nodesToCalculate; i++) {
            privateKey.nextThreehash.calculateNextNodes();
        }
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
        msgBinaryString = HelperFunctions.stringPadding(l1, wBytes, msgBinaryString);
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
        controlSumBinaryString = HelperFunctions.stringPadding(l2, wBytes, controlSumBinaryString);
        for (int i = 0; i < l2; i++) {
            privatePart = WOTSkeyGenerator.getPrivPart(l, f, i + l1, seed);
            msgPartBaseW = Integer.parseInt(controlSumBinaryString.substring(actualMsgIndex, nextMsgIndex), 2);
            actualMsgIndex = nextMsgIndex;
            nextMsgIndex += wBytes;
            signature[l1 + i] = f.composeFunction(x, privatePart, msgPartBaseW);
        }

        return signature;
    }

    public void replaceLowerWithNext(int treeIndex) {
        int kLA = params.kL;
        int kLB = params.kL;
        if(params.treeGrowth % 2 != 0 && treeIndex%2 == 0){
            //params.kL ++;
            kLA++;
        } else {
            kLB++;
        }
        privateKey.lowerGenState = privateKey.nextGenState;
        privateKey.lowerPathComputation = new PathComputation(params.nextH,kLA,params.n,params.lL,keysKeeper.publicKey,params.wL
                ,privateKey.nextGenState,privateKey.nextThreehash.authNext,privateKey.nextThreehash.treeHashArrayNext,privateKey.nextThreehash.retainNext);
        byte[] initialState = new byte[n];
        fillBytesRandomly(initialState);
        privateKey.nextGenState = initialState;
        byte [] lowerRootValue = privateKey.nextThreehash.stack.pop().value;
        keysKeeper.publicKey.lowerRoot = lowerRootValue;
        SignatureGenerator.signLowerTree(privateKey, params.n, params.lu1, params.lu2, params.wU, keysKeeper.publicKey.X, lowerRootValue);
        params.lowerH = params.nextH;
        params.nextH = params.lowerH + params.treeGrowth;
        params.lowerSize = params.nextSize;
        params.nextSize = (int) (params.nextSize*Math.pow(2,params.treeGrowth));
        privateKey.nextThreehash = new TreehashNext(new Stack<>(),params.nextH,params.bitmaskMain,params.bitmaskLTree,params.n,params.lL,params.X,params.wL,kLB,privateKey.nextGenState);
    }

}
