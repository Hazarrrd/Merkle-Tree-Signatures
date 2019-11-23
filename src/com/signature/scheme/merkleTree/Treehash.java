package com.signature.scheme.merkleTree;

import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.merkleTree.MTreeOperations.computeParent;
import static com.signature.scheme.merkleTree.MTreeOperations.leafCalc;
import static com.signature.scheme.tools.HelperFunctions.reverseStack;

public class Treehash {
    private int index;
    public Stack<Node> stack;
    public FSGenerator generator;
    public Node node = null;
    int height;
    public byte[][] maskL;
    public byte[][] maskMain;
    public final int maxHeight;
    public int n;
    public int l;
    public byte[] x;
    public int w;

    public Treehash(Stack<Node> stack, int maxHeight, byte[][] maskMain,byte[][] maskL, int n, int l, byte[] x, int w) {
        this.stack = stack;
        this.maxHeight = maxHeight;
        this.height = Integer.MAX_VALUE;
        this.maskL = maskL;
        this.maskMain = maskMain;
        this.n = n;
        this.l = l;
        this.x = x;
        this.w = w;
    }

    public static Stack<Node> standardTreehash(Node leaf, Stack<Node> stack, byte[][] mask) {
        Node top;
        while (stack.size() > 0 && leaf.height == stack.peek().height) {
            top = stack.pop();
            leaf = computeParent(top, leaf, mask[top.height]);
        }
        stack.push(leaf);
        return stack;
    }

    public static Stack<Node> standardTreehash(Node leaf, Stack<Node> stack, byte[][] mask, Node[] auth, Treehash[] treeHashArray, Stack<Node>[] retain, int treeHeight, int K) {
        Node top;
        while (stack.size() > 0 && leaf.height == stack.peek().height) {
            if (leaf.index == 1)
                auth[leaf.height] = leaf;
            else if (leaf.height <= (treeHeight - K - 1) && leaf.index == 3) {
                treeHashArray[leaf.height].node = leaf;
            } else if (leaf.height > (treeHeight - K - 1) && leaf.height <= treeHeight - 2) {
                int limit = (int) (Math.pow(2, treeHeight - leaf.height - 1) - 2);
                for (int i = limit; i >= 0; i--) {
                    if (leaf.index == 2 * i + 3) {
                        retain[leaf.height].push(leaf);
                        break;
                    }
                }
            }
            top = stack.pop();
            leaf = computeParent(top, leaf, mask[top.height]);
        }
        stack.push(leaf);
        reverseStack(retain);
        return stack;
    }

    public static Stack<Node> forceThreehashToEnd(Stack<Node> stack, byte[][] mask) {

        if (stack.size() == 1)
            return stack;
        Node last = stack.pop();
        int h = stack.peek().height;
        while (h > last.height) {
            last.height++;
        }
        return standardTreehash(last, stack, mask);
    }

    //ULEPSZ POTEM NODE,ŻEBY DOPIERO NA KONIEC SIĘ WYPEŁNIAŁ
    private void doAlgorithm(byte[] seed) {
        Node leaf = leafCalc(this.n, seed, this.l, this.x, this.w, this.maskL,index);
        Node top;
        while (stack.size() > 0 && leaf.height == this.stack.peek().height) {
            top = this.stack.pop();
            leaf = computeParent(top, leaf, this.maskMain[top.height]);
        }
        if (node != null) {
            if (node.height != leaf.height) {
                this.stack.push(leaf);
                this.height = leaf.height;
            } else {
                node = computeParent(node, leaf, this.maskMain[node.height]);
                if (node.height != maxHeight) {
                    this.height = node.height;
                }
                else {
                    this.height = Integer.MAX_VALUE;
                }
            }
        } else {
            this.node = leaf;
            if(maxHeight!=0) {
                this.height = 0;
            } else {
                this.height = Integer.MAX_VALUE;
            }
        }
    }

    public void initialize(byte[] seedNext, int index) {
        generator = new FSGenerator(new PseudorndFunction(n),new PseudorndFunction(n),seedNext);
        this.node = null;
        this.index = index;
        this.height = this.maxHeight;
    }

    public void update() {
        index++;
        byte[] seed = generator.nextStateAndSeed();
        doAlgorithm(seed);
    }


}
