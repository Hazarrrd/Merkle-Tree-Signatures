package com.signature.scheme.merkleTree;

import com.signature.scheme.keys.PublicKey;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.merkleTree.MTreeOperations.computeParent;
import static com.signature.scheme.merkleTree.MTreeOperations.leafCalc;
import static java.lang.Math.*;

public class PathComputation {

    private int firstLeftNode;
    private int treeHeight;
    private int k;
    public Node[] auth;
    private Node[] keep;
    private Stack<Node>[] retainStack;
    private byte[][] seedNextArray;
    private Treehash[] treehashArray;
    public int leafNumber;
    private int updatesNumber;
    FSGenerator generator;
    byte[][] maskMain;
    byte[][] maskL;
    public byte[] seed;
    private int n;
    private int l;
    private byte[] x;
    private int w;
    private int treehashBound;
    public int leafIndex;

    public PathComputation(int treeHeight, int k, int n, int l, PublicKey publicKey, int w, byte[] seed, Node[] auth, Treehash[] treehashArray, Stack<Node>[] retainStack) {
        this.treeHeight = treeHeight;
        this.k = k;
        this.n = n;
        this.l = l;
        this.x = publicKey.X;
        this.w = w;
        this.generator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), seed);
        this.seedNextArray = new byte[treeHeight - k][n];
        this.seed = seed;
        this.maskL = publicKey.bitmaskLTree;
        this.maskMain = publicKey.bitmaskMain;
        this.treehashArray = treehashArray;
        this.keep = new Node[treeHeight - 1];
        this.auth = auth;
        this.retainStack = retainStack;
        int limit;
        int j = 0;
        for (int i = 0; i < treeHeight-k; i++) {
            limit = (int) (3 * Math.pow(2, i));
            while (j < limit) {
                generator.nextState();
                j++;
            }
            seedNextArray[i] = generator.state;
        }
        leafNumber = (int) pow(2, this.treeHeight);
        updatesNumber = (this.treeHeight - k) / 2;
        treehashBound = this.treeHeight - this.k - 1;
        leafIndex = 0;
    }

    public void doAlgorithm() {
        generator.state = seed;
        byte[] seedForPK = generator.nextStateAndSeed();
        seed = generator.state;

        for (int i = 0; i < treeHeight - k; i++) {
            generator.state = seedNextArray[i];
            generator.nextState();
            seedNextArray[i] = generator.state;
        }

        //Setting firstLeftNode
        if (leafIndex % 2 == 0) {
            firstLeftNode = 0;
        } else {
            int h = 1;
            int div = 2;
            int index = leafIndex + 1;
            while (index % div == 0) {
                div *= 2;
                h++;
            }
            firstLeftNode = h - 1;
        }

        //Saveing node for left authentiacation node computation in future
        if (firstLeftNode < (treeHeight - 1) && floor(leafIndex / (int) Math.pow(2, firstLeftNode + 1)) % 2 == 0) {
            keep[firstLeftNode] = auth[firstLeftNode];
        }

        //Computing left authentiaction node
        if (firstLeftNode == 0) {
            auth[0] = leafCalc(this.n, seedForPK, this.l, this.x, this.w, maskL,leafIndex);
        } else {
            auth[firstLeftNode] = computeParent(auth[firstLeftNode - 1], keep[firstLeftNode - 1], maskMain[firstLeftNode - 1]);
            keep[firstLeftNode - 1] = null;

            //Computing right autheniaction nodes on heights [0,firstLeftNode-1]
            for (int h = 0; h < firstLeftNode; h++) {
                if (h <= treehashBound) {
                    auth[h] = treehashArray[h].node;
                } else {
                    auth[h] = retainStack[h].pop();
                }
            }

            //Initialize threehash instances for heights 0 .. min{firstLeftNode-1, treeHeight - k - 1}
            int minimum = min(firstLeftNode - 1, treehashBound);
            for (int h = 0; h <= minimum; h++) {
                int index = (int) (leafIndex + 1 + 3 * pow(2, h));
                if (index < this.leafNumber) {
                    this.treehashArray[h].initialize(seedNextArray[h], index);
                }
            }
        }

        //(treeHeight-k)/2 updates of threehash
        Treehash toUpdate = null;
        int min = Integer.MAX_VALUE;
        for (int i = 0; i < updatesNumber; i++) {
            for (int j = 0; j <= treehashBound; j++) {
                if (min > treehashArray[j].height) {
                    toUpdate = treehashArray[j];
                    min = toUpdate.height;
                }
            }
            if (toUpdate != null) {
                toUpdate.update();
                min = Integer.MAX_VALUE;
                toUpdate = null;
            }
        }
        leafIndex++;
    }
}
