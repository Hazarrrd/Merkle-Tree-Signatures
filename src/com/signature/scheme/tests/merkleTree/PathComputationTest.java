package com.signature.scheme.tests.merkleTree;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.keys.PublicKey;
import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.PathComputation;
import com.signature.scheme.merkleTree.Treehash;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.PseudorndFunction;
import org.junit.jupiter.api.Test;

import java.util.Stack;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PathComputationTest {

    @Test
    void doAlgorithm() {
        Stack<Node> stack;
        byte[][] publicKey;

        ParametersBase params = new ParametersBase();
        int size = params.upperSize;
        publicKey = new byte[size][params.n];
        stack = new Stack<Node>();
        Node[] auth = new Node[params.upperH];
        Treehash[] treeHashArray = new Treehash[params.upperH - params.kU];
        Stack<Node>[] retain = new Stack[params.upperH - 1];
        for (int i = params.upperH - params.kU; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for (int i = 0; i < treeHashArray.length; i++) {
            treeHashArray[i] = new Treehash(new Stack<Node>(), i, params.bitmaskMain, params.bitmaskLTree, params.n, params.lU, params.X, params.wU);
        }

        FSGenerator generator = new FSGenerator(new PseudorndFunction(params.n), new PseudorndFunction(params.n), params.seed);

        for (int i = 0; i < size; i++) {
            byte[] pkseed = generator.nextStateAndSeed();
            publicKey[i] = MTreeOperations.leafCalc(params.n, pkseed, params.lU, params.X, params.wU, params.bitmaskLTree, i).value;

            stack = Treehash.standardTreehash(new Node(0, publicKey[i], i), stack, params.bitmaskMain, auth, treeHashArray, retain, params.upperH, params.kU);

        }
        PublicKey publicKeyMTree = new PublicKey();
        publicKeyMTree.X = params.X;
        publicKeyMTree.bitmaskLTree = params.bitmaskLTree;
        publicKeyMTree.bitmaskMain = params.bitmaskMain;
        PathComputation pathComputation = new PathComputation(params.upperH, params.kU, params.n, params.lU, publicKeyMTree, params.wU, params.seed, auth, treeHashArray, retain);
        generator = new FSGenerator(new PseudorndFunction(params.n), new PseudorndFunction(params.n), params.seed);

        for (int i = 0; i < size - 1; i++) {
            auth = pathComputation.auth;
            byte[] pkseed = generator.nextStateAndSeed();
            Node node = MTreeOperations.leafCalc(params.n, pkseed, params.lU, params.X, params.wU, params.bitmaskLTree, i);

            assertArrayEquals(node.value, publicKey[i]);
            for (int j = 1; j <= params.upperH; j++) {

                if (node.index % 2 == 0) {
                    node = MTreeOperations.computeParent(node, auth[j - 1], params.bitmaskMain[j - 1]);

                } else {
                    node = MTreeOperations.computeParent(auth[j - 1], node, params.bitmaskMain[j - 1]);
                }
            }

            assertEquals(stack.size(), 1);
            assertEquals(stack.peek().height, params.upperH);
            assertEquals(node.height, stack.peek().height);
            assertEquals(node.index, 0);
            assertEquals(stack.peek().index, node.index);
            assertEquals(stack.peek().value.length, node.value.length);
            assertArrayEquals(node.value, stack.peek().value);


            pathComputation.doAlgorithm();
        }

    }
}