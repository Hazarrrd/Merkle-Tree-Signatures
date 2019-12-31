package com.signature.scheme.algorithm.keys;

import com.signature.scheme.algorithm.merkleTree.*;
import com.signature.scheme.algorithm.signing.SignatureGenerator;
import com.signature.scheme.algorithm.tools.FSGenerator;
import com.signature.scheme.algorithm.tools.HashFunction;
import com.signature.scheme.algorithm.tools.HelperFunctions;
import com.signature.scheme.algorithm.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.algorithm.tools.HelperFunctions.fillBytesRandomly;

/**
 * Class generates and keeps keys of the scheme.
 */
public class KeysKeeper {

    //Private Key
    public PrivateKey privateKey;
    //Public Key
    public PublicKey publicKey;
    //Parameters
    public ParametersBase params;

    public KeysKeeper(int m, int n, int kU, int kL, int upperH, int lowerH, int wL, int wU, int treeGrowth) {
        byte[] x = KeysKeeper.generateX(n);
        params = new ParametersBase(m, n, kU, kL, upperH, lowerH, wL, wU, x, treeGrowth);

    }

    public KeysKeeper(ParametersBase params) {
        this.params = params;

    }

    public void generateKeys() {

        privateKey = new PrivateKey();
        publicKey = new PublicKey();
        publicKey.bitmaskMain = params.bitmaskMain;
        publicKey.bitmaskLTree = params.bitmaskLTree;
        publicKey.X = params.X;

        HashFunction.setFunction(params.hashFunctionKey, params.n);
        //generate upper and lower trees
        byte[] lowerRoot = generateTrees();
        //sign lower by upper
        SignatureGenerator.signLowerTree(privateKey, params.n, params.lu1, params.lu2, params.wU, publicKey.X, lowerRoot);
    }

    public byte[] generateTrees() {

        FSGenerator lowerGenerator = generateFSGenerator(params.n);
        FSGenerator nextGenerator = generateFSGenerator(params.n);
        FSGenerator upperGenerator = generateFSGenerator(params.n);

        privateKey.lowerGenState = lowerGenerator.initialState;
        privateKey.nextGenState = nextGenerator.initialState;
        privateKey.upperGenState = upperGenerator.initialState;
        int kLa = params.kL;
        if (params.treeGrowth % 2 != 0) {
            kLa++;
        }
        privateKey.nextThreehash = new TreehashNext(new Stack<Node>(), params.nextH, params.bitmaskMain, params.bitmaskLTree, params.n, params.lL, params.X, params.wL, kLa, privateKey.nextGenState);
        Node[] auth = new Node[params.upperH];
        Treehash[] treeHashArray = new Treehash[params.upperH - params.kU];
        Stack<Node>[] retain = new Stack[params.upperH - 1];
        for (int i = params.upperH - params.kU; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for (int i = 0; i < treeHashArray.length; i++) {
            treeHashArray[i] = new Treehash(new Stack<Node>(), i, params.bitmaskMain, params.bitmaskLTree, params.n, params.lU, params.X, params.wU);
        }

        publicKey.upperRoot = generateRootOfTree(upperGenerator, params.lU, params.wU, auth, treeHashArray, retain, params.upperH, params.kU, params.n);
        privateKey.upperPathComputation = new PathComputation(params.upperH, params.kU, params.n, params.lU, publicKey, params.wU, privateKey.upperGenState, auth, treeHashArray, retain);

        auth = new Node[params.lowerH];
        treeHashArray = new Treehash[params.lowerH - params.kL];
        retain = new Stack[params.lowerH - 1];
        for (int i = params.lowerH - params.kL; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for (int i = 0; i < treeHashArray.length; i++) {
            treeHashArray[i] = new Treehash(new Stack<Node>(), i, params.bitmaskMain, params.bitmaskLTree, params.n, params.lL, params.X, params.wL);
        }

        byte[] lowerRoot = generateRootOfTree(lowerGenerator, params.lL, params.wL, auth, treeHashArray, retain, params.lowerH, params.kL, params.n);
        privateKey.lowerPathComputation = new PathComputation(params.lowerH, params.kL, params.n, params.lL, publicKey, params.wL, privateKey.lowerGenState, auth, treeHashArray, retain);
        return lowerRoot;
    }

    public byte[] generateRootOfTree(FSGenerator generator, int l, int w, Node[] auth, Treehash[] treeHashArray, Stack<Node>[] retain, int treeHeight, int K, int n) {
        int howManyKeys = (int) Math.pow(2, treeHeight);
        Node leaf;
        Stack<Node> stack = new Stack<Node>();

        for (int i = 0; i < howManyKeys; i++) {
            leaf = MTreeOperations.leafCalc(n, generator.nextStateAndSeed(), l, publicKey.X, w, publicKey.bitmaskLTree, i);
            stack = Treehash.standardTreehash(leaf, stack, publicKey.bitmaskMain, auth, treeHashArray, retain, treeHeight, K);
        }
        return stack.pop().value;

    }


    private FSGenerator generateFSGenerator(int n) {
        byte[] initialState = new byte[n];
        fillBytesRandomly(initialState);
        return new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), initialState);
    }

    public static byte[] generateX(int n) {
        byte[] X = new byte[n];
        HelperFunctions.fillBytesRandomly(X);
        return X;
    }

}
