package com.signature.scheme.algorithm.merkleTree;

import com.signature.scheme.algorithm.keys.WOTSkeyGenerator;
import com.signature.scheme.algorithm.tools.HashFunction;
import com.signature.scheme.algorithm.tools.PseudorndFunction;

import java.util.Stack;

import static com.signature.scheme.algorithm.tools.HelperFunctions.xorTwoByteArrays;

/**
 * Class holds functions that are used on Merkle Tree.
 */
public class MTreeOperations {

    //Computes parent from left and right child nodes.
    public static Node computeParent(Node left, Node right, byte[] mask) {
        int n = mask.length / 2;
        byte[] value = new byte[mask.length];
        System.arraycopy(left.value, 0, value, 0, n);
        System.arraycopy(right.value, 0, value, n, n);
        value = xorTwoByteArrays(value, mask);
        Node parent = new Node(right.height + 1, HashFunction.computeHash(value), left.index / 2);
        return parent;
    }

    //Computes leaf of Merkle Tree
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

    //Computes leaf of Merkle Tree
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

    //Computes Merkle tree's root using leaf and this leaf's authentication path
    public static Node computeRoot(int h, int index, Node node, Node[] auth, byte[][] bitmask) {
        for (int i = 0; i < h; i++) {
            if (Math.floor(index / Math.pow(2, i)) % 2 == 0) {
                node = MTreeOperations.computeParent(node, auth[i], bitmask[i]);
            } else {
                node = MTreeOperations.computeParent(auth[i], node, bitmask[i]);
            }
        }
        return node;
    }

}
