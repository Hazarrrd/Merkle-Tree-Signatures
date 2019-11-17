package com.signature.scheme;

import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.tools.HelperFunctions.*;

public class KeyGenerator {

    //Private Key
    PrivateKey privateKey;
    //Public Key
    PublicKey publicKey;
    //security parameter
    int n;
    //msg length
    int m;
    // overall height even
    int overallH;
    // internal height = overallH/2
    int internalH;
    //Winternitz parameter for upper tree
    int wU;
    //Winternitz parmeter for lower tree
    int wL;
    //Path Computation Algorithm parameter k for upper tree, such that internalH - kU is even and ((internalH-kU)/2) + 1 <= pow(2,internalH-kL+1)
    int kU;
    //Path Computation Algorithm parameter k for lower tree, such that internalH - kL is even and ((internalH-kU)/2) + 1 <= pow(2,internalH-kL+1)
    int kL;
    //TO DO X

    //PAMIĘTAJ ZEBY ZALADOWAC KONSTRUKTOOOOOOOOR

    public void generateKeys() {

        setHashFuncton(n);
        int lu1 = (int) Math.ceil(n/log2(wU));
        int lu2 = (int) Math.floor(log2(lu1*(wU-1))/log2(wU));
        int lU = lu1 + lu2;
        int ll1 = (int) Math.ceil(m/log2(wL));
        int ll2 = (int) Math.floor(log2(ll1*(wL-1))/log2(wL));
        int lL = ll1 + ll2;

        if(this.internalH != 0 ){
            System.err.println("Height should be even!");
            return;
        }
        publicKey.bitmaskLTree = generateBitmask(Math.max(lU,lL),true);
        publicKey.bitmaskMain = generateBitmask(this.internalH,false);
        publicKey.X = generateX();
        FSGenerator lowerGenerator = generateFSGenerator();
        FSGenerator nextGenerator = generateFSGenerator();
        FSGenerator upperGenerator = generateFSGenerator();
        privateKey.lowerGenState = generateFSGenerator().initialState;
        privateKey.nextGenState = generateFSGenerator().initialState;
        privateKey.upperGenState = generateFSGenerator().initialState;

        Node[] auth = new Node[internalH];
        Treehash[] treeHashArray = new Treehash[internalH-kU];
        //Rozwarz zmianę wielkości tablicy
        Stack<Node>[] retain = new Stack[internalH-1];
        for(int i =0;i<retain.length;i++)
            retain[i] = new Stack<Node>();

        publicKey.upperRoot = generateRootOfTree(upperGenerator,publicKey.X,lU,wU,publicKey.bitmaskMain,publicKey.bitmaskLTree,auth,treeHashArray,retain,internalH,kU);
        privateKey.upperPathState = new PathComputation(internalH,kU,n,lU,publicKey.X,wU,privateKey.upperGenState,publicKey.bitmaskLTree,publicKey.bitmaskMain,auth,treeHashArray,retain);

        auth = new Node[internalH];
        treeHashArray = new Treehash[internalH-kU];
        //Rozwarz zmianę wielkości tablicy
        retain = new Stack[internalH-1];
        for(int i =0;i<retain.length;i++)
            retain[i] = new Stack<Node>();

        byte[] lowerRoot = generateRootOfTree(lowerGenerator,publicKey.X,lL,wL,publicKey.bitmaskMain,publicKey.bitmaskLTree,auth,treeHashArray,retain,internalH,kL);
        privateKey.lowerPathState = new PathComputation(internalH,kL,n,lL,publicKey.X,wL,privateKey.lowerGenState,publicKey.bitmaskLTree,publicKey.bitmaskMain,auth,treeHashArray,retain);

        //SIGN lower by upper
        SignatureGenerator.signLowerTree(privateKey,n,lu1,lu2,wU,publicKey.X,lowerRoot,internalH);








    }

    private byte[] generateRootOfTree(FSGenerator generator, byte[] x, int l, int w, byte[][] bitmask, byte[][] lBitmask, Node[] auth,  Treehash[] treeHashArray, Stack<Node>[] retain,int Height,int K){
        int howManyKeys = (int) Math.pow(2,this.internalH);
        Node leaf;
        Stack <Node> stack = new Stack<Node>();

        for(int i=0;i<howManyKeys; i++){
            leaf = MTreeOperations.leafCalc(this.n,generator.nextStateAndSeed(),l,x,w,lBitmask,i);
            stack = Treehash.standardTreehash(leaf,stack,bitmask,auth,treeHashArray,retain,Height,K);
        }
        reverseStack(retain);
        return stack.pop().value;

    }


    private FSGenerator generateFSGenerator() {
        byte[] initialState = new byte[this.n];
        fillBytesRandomly(initialState);
        return new FSGenerator(new PseudorndFunction(this.n),new PseudorndFunction(this.n),initialState);
    }

    private byte[] generateX() {
        byte[] X = new byte[this.n];
        fillBytesRandomly(X);
        return X;
    }

    public byte[][] generateBitmask(int treeSize, Boolean LTree) {

        int size;
        if (LTree) {
            size = ceilLogTwo(treeSize);
        } else {
            size = treeSize;
        }
        byte[][] bitmasksArray = new byte[size][2 * this.n];


        for (int i = 0; i < size; i++) {
            fillBytesRandomly(bitmasksArray[i]);
        }


        return bitmasksArray;
    }





}
