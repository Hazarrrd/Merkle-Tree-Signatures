package com.signature.scheme.merkleTree;

import com.signature.scheme.tools.FSGenerator;

import java.util.Stack;

import static com.signature.scheme.merkleTree.MTreeOperations.computeParent;
import static com.signature.scheme.merkleTree.MTreeOperations.leafCalc;

public class Treehash {
    private int index;
    Stack<Node> stack;
    FSGenerator generator;
    Node node = null;
    int height;
    byte[][] mask;
    final int maxHeight;
    private int n;
    private byte[] seedActive;
    private int l;
    private byte[] x;
    private int w;

    public Treehash(Stack<Node> stack, int maxHeight, byte[][] mask, int n, int l, byte[] x, int w) {
        this.stack = stack;
        this.maxHeight = maxHeight;
        this.height = Integer.MAX_VALUE;
        this.mask = mask;
        this.n = n;
        this.l = l;
        this.x = x;
        this.w = w;
    }

    public static Stack<Node> standardTreehash(Node leaf,Stack<Node> stack,byte[][] mask) {
        Node top;
        while (leaf.height == stack.peek().height) {
            top = stack.pop();
            leaf = computeParent(top, leaf,mask[top.height+1]);
        }
        stack.push(leaf);
        return stack;
    }

    public static Stack<Node> standardTreehash(Node leaf,Stack<Node> stack,byte[][] mask,Node[] auth,Treehash[] treeHashArray,Stack<Node>[] retain, int treeHeight, int K) {
        Node top;
        while (leaf.height == stack.peek().height) {
            if(leaf.index == 1)
                auth[leaf.height] = leaf;
            else if(leaf.height <= (treeHeight-K-1) && leaf.index == 3){
                treeHashArray[leaf.height].node = leaf;
            } else if(leaf.height > (treeHeight-K-1) && leaf.height <= treeHeight-2){
                int limit = (int) (Math.pow(2,treeHeight-leaf.height-1)-2);
                for (int i = limit;i>=0;i--){
                    if(leaf.index == 3*i + 3){
                        retain[leaf.height].push(leaf);
                    }
                }
            }
            top = stack.pop();
            leaf = computeParent(top, leaf,mask[top.height+1]);
        }
        stack.push(leaf);
        return stack;
    }

    public static Stack<Node> forceThreehashToEnd(Stack<Node> stack,byte[][] mask){

        if(stack.size()==1)
            return stack;
        Node last = stack.pop();
        int h = stack.peek().height;
        while(h > last.height){
            last.height++;
        }
        return standardTreehash(last,stack,mask);
    }

    //ULEPSZ POTEM NODE,ŻEBY DOPIERO NA KONIEC SIĘ WYPEŁNIAŁ
    private void doAlgorithm(byte[] seed) {
        Node leaf = leafCalc(this.n,seed,this.l,this.x,this.w,this.mask,index);
        Node top;
        while (leaf.height== this.stack.peek().height) {
            top = this.stack.pop();
            leaf = computeParent(top, leaf,this.mask[top.height+1]);
        }
        if (node != null) {
            if(node.height!=leaf.height) {
                this.stack.push(leaf);
                this.height = leaf.height;
            }
            else {
                node = computeParent(node, leaf,this.mask[node.height+1]);
                if(node.height!=maxHeight)
                    this.height = node.height;
                else this.height = Integer.MAX_VALUE;
            }
        } else {
            this.node = leaf;
            this.height = 0;
        }
    }

    public void initialize(byte[] seedNext,int index) {
        this.seedActive = seedNext;
        this.index = index;
    }

    public void update() {
        byte[] seed = generator.next();
        doAlgorithm(seed);
    }


}
