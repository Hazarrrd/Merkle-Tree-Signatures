package com.signature.scheme.merkleTree;

import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Stack;

/**
 * Class represents Treehash algorithm, that is used to build next lower tree.
 */
public class TreehashNext extends Treehash {
    public int index;
    public Node[] authNext;
    public Treehash[] treeHashArrayNext;
    public Stack<Node>[] retainNext;
    int k;

    public TreehashNext(Stack<Node> stack, int maxHeight, byte[][] maskMain, byte[][] maskL, int n, int l, byte[] x, int w, int k, byte[] seedFS) {
        super(stack, maxHeight, maskMain, maskL, n, l, x, w);
        index = 0;
        this.k = k;

        this.authNext = new Node[maxHeight];
        this.treeHashArrayNext = new Treehash[maxHeight - k];
        this.retainNext = new Stack[maxHeight - 1];
        for (int i = maxHeight - k; i < retainNext.length; i++)
            this.retainNext[i] = new Stack<Node>();
        for (int i = 0; i < treeHashArrayNext.length; i++) {
            this.treeHashArrayNext[i] = new Treehash(new Stack<Node>(), i, maskMain, maskL, n, l, x, w);
        }
        this.generator = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), seedFS);
    }

    public void calculateNextNodes() {
        Node leaf = MTreeOperations.leafCalc(this.n, this.generator.nextStateAndSeed(), this.l, this.x, this.w, this.maskL, this.index);
        this.stack = Treehash.standardTreehash(leaf, this.stack, this.maskMain, this.authNext, this.treeHashArrayNext, this.retainNext, this.maxHeight, this.k);
        index++;
    }
}
