package com.signature.scheme.merkleTree;

import com.signature.scheme.WOTSkeyGenerator;
import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.tools.HelperFunctions.xorTwoByteArrays;

public class MTreeOperations {

    private MTreeOperations() {
    }

    public static Node computeParent(Node top, Node leaf, byte[] mask) {
        int n = mask.length / 2;
        byte[] value = new byte[mask.length];
        System.arraycopy(top.value, 0, value, 0, n);
        System.arraycopy(leaf.value, 0, value, n, n);
        value = xorTwoByteArrays(value, mask);
        Node parent = new Node(leaf.height + 1, HashFunction.computeHash(value), top.index / 2);
        return parent;
    }

    public static Node leafCalc(int n, byte[] seed, int l, byte[] x, int w, byte[][] mask, int index) {

        PseudorndFunction f = new PseudorndFunction(n);

        Stack<Node> stack = new Stack<Node>();
        byte[] privatePart;
        byte[] publicPart;


        for (int i = 0; i < l; i++) {
            privatePart = WOTSkeyGenerator.getPrivPart(l, f, i, seed);
            publicPart = WOTSkeyGenerator.getPublicPart(x, w, f, privatePart);
            stack = Treehash.standardTreehash(new Node(0, publicPart, i), stack, mask);
        }
        stack = Treehash.forceThreehashToEnd(stack, mask);
        Node result = stack.pop();
        result.height = 0;
        result.index = index;
        return result;
    }

    public static Node leafCalc(int n, int l, byte[][] publicKey, byte[][] mask, int index) {

        PseudorndFunction f = new PseudorndFunction(n);

        Stack<Node> stack = new Stack<Node>();
        byte[] publicPart;

        for (int i = 0; i < l; i++) {
            publicPart = publicKey[i];
            stack = Treehash.standardTreehash(new Node(0, publicPart, i), stack, mask);
        }
        stack = Treehash.forceThreehashToEnd(stack, mask);
        Node result = stack.pop();
        result.height = 0;
        result.index = index;
        return result;
    }

}
