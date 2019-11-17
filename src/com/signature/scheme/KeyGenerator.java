package com.signature.scheme;

import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.tools.HelperFunctions.*;

public class KeyGenerator {

    //Private Key
    PrivateKey privateKey;
    //Public Key
    PublicKey publicKey;
    //Parameters
    ParametersBase params;

    public KeyGenerator(int m, int n, int kU, int kL, int upperH, int lowerH, int wL, int wU){
        privateKey = new PrivateKey();
        publicKey = new PublicKey();
        byte[] x = KeyGenerator.generateX(n);
        params = new ParametersBase(m,n,kU,kL,upperH,lowerH,wL,wU,x);

        publicKey.bitmaskMain = params.bitmaskMain;
        publicKey.bitmaskLTree = params.bitmaskLTree;
        publicKey.X = params.X;
    }



    public void generateKeys() {
        HelperFunctions.setHashFuncton(params.n);

        FSGenerator lowerGenerator = generateFSGenerator(params.n);
        FSGenerator nextGenerator = generateFSGenerator(params.n);
        FSGenerator upperGenerator = generateFSGenerator(params.n);

        privateKey.lowerGenState = lowerGenerator.initialState;
        privateKey.nextGenState = nextGenerator.initialState;
        privateKey.upperGenState = upperGenerator.initialState;

        Node[] auth = new Node[params.upperH];
        Treehash[] treeHashArray = new Treehash[params.upperH - params.kU];
        //Rozwaz zmianę wielkości tablicy
        Stack<Node>[] retain = new Stack[params.upperH - 1];
        for (int i = params.upperH -params.kU; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for(int i =0;i<treeHashArray.length;i++){
            treeHashArray[i] = new Treehash(new Stack<Node>(),i,params.bitmaskMain,params.bitmaskLTree,params.n,params.lU,params.X,params.wU);
        }

        publicKey.upperRoot = generateRootOfTree(upperGenerator, publicKey, params.lU, params.wU, auth, treeHashArray, retain, params.upperH, params.kU,params.n);
        privateKey.upperPathState = new PathComputation(params.upperH, params.kU, params.n, params.lU, publicKey, params.wU, privateKey.upperGenState, auth, treeHashArray, retain);

        auth = new Node[params.lowerH];
        treeHashArray = new Treehash[params.lowerH - params.kL];
        //Rozwaz zmianę wielkości tablicy
        retain = new Stack[params.lowerH - 1];
        for (int i = params.lowerH -params.kL; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for(int i =0;i<treeHashArray.length;i++){
            treeHashArray[i] = new Treehash(new Stack<Node>(),i,params.bitmaskMain,params.bitmaskLTree,params.n,params.lL,params.X,params.wL);
        }

        byte[] lowerRoot = generateRootOfTree(lowerGenerator, publicKey, params.lL, params.wL, auth, treeHashArray, retain, params.lowerH, params.kL,params.n);
        privateKey.lowerPathState = new PathComputation(params.lowerH, params.kL, params.n, params.lL, publicKey, params.wL, privateKey.lowerGenState, auth, treeHashArray, retain);

        //SIGN lower by upper
        SignatureGenerator.signLowerTree(privateKey, params.n, params.lu1, params.lu2, params.wU, publicKey.X, lowerRoot, params.lowerH);
    }

    private byte[] generateRootOfTree(FSGenerator generator,PublicKey publicKey, int l, int w, Node[] auth, Treehash[] treeHashArray, Stack<Node>[] retain, int treeHeight, int K, int n) {
        int howManyKeys = (int) Math.pow(2, treeHeight);
        Node leaf;
        Stack<Node> stack = new Stack<Node>();

        for (int i = 0; i < howManyKeys; i++) {
            leaf = MTreeOperations.leafCalc(n, generator.nextStateAndSeed(), l, publicKey.X, w, publicKey.bitmaskLTree,i);
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
