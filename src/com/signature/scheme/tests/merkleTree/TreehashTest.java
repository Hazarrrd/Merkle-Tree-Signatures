package com.signature.scheme.tests.merkleTree;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.merkleTree.Treehash;
import com.signature.scheme.tools.HelperFunctions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Stack;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TreehashTest {

    ParametersBase params;
    Stack<Node> stack;
    byte[][] publicKey;

    @BeforeEach
    void setUp() {
        params = new ParametersBase();
        publicKey = new byte[params.maxL][params.n];
        for (int i = 0; i < params.maxL; i++)
            HelperFunctions.fillBytesRandomly(publicKey[i]);
        stack = new Stack<Node>();
    }

    @Test
    void standardTreehash() {
        int size = params.upperSize;
        publicKey = new byte[size][params.n];
        stack = new Stack<Node>();
        for (int i = 0; i < size; i++)
            HelperFunctions.fillBytesRandomly(publicKey[i]);
        for (int i = 0; i < size; i++) {
            stack = Treehash.standardTreehash(new Node(0, publicKey[i], i), stack, params.bitmaskMain);
        }
        assertEquals(stack.size(), 1);
        assertEquals(stack.peek().height, params.upperH);
        assertEquals(stack.peek().value.length, params.n);
        assertEquals(stack.peek().index, 0);
    }

    @Test
    void StandardTreehasGenArrays() {
        int size = params.upperSize;
        publicKey = new byte[size][params.n];
        stack = new Stack<Node>();
        Node[] auth = new Node[params.upperH];
        Treehash[] treeHashArray = new Treehash[params.upperH - params.kU];
        Stack<Node>[] retain = new Stack[params.upperH - 1];
        for (int i = params.upperH - params.kU; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for (int i = 0; i < treeHashArray.length; i++) {
            treeHashArray[i] = new Treehash(new Stack<Node>(), params.upperH, params.bitmaskMain, params.bitmaskLTree, params.n, params.lU, params.X, params.wU);
        }

        for (int i = 0; i < size; i++)
            HelperFunctions.fillBytesRandomly(publicKey[i]);

        for (int i = 0; i < size; i++) {
            stack = Treehash.standardTreehash(new Node(0, publicKey[i], i), stack, params.bitmaskMain, auth, treeHashArray, retain, params.upperH, params.kU);
        }
        assertEquals(stack.size(), 1);
        assertEquals(stack.peek().height, params.upperH);
        assertEquals(stack.peek().value.length, params.n);
        assertEquals(stack.peek().index, 0);


        for (int i = 0; i < params.upperH; i++) {
            assertEquals(i, auth[i].height);
            assertEquals(1, auth[i].index);
            assertEquals(params.n, auth[i].value.length);
        }

        for (int i = 0; i < treeHashArray.length; i++) {
            assertEquals(i, treeHashArray[i].node.height);
            assertEquals(3, treeHashArray[i].node.index);
            assertEquals(params.n, treeHashArray[i].node.value.length);
        }
        assertEquals(retain.length, params.upperH - 1);
        for (int i = params.upperH - params.kU; i < retain.length; i++) {
            int limit = (int) (Math.pow(2, params.upperH - i - 1) - 2);
            for (int j = 0; j <= limit; j++) {
                assertEquals(i, retain[i].peek().height);
                assertEquals(params.n, retain[i].peek().value.length);
                assertEquals(3 + 2 * j, retain[i].pop().index);
            }
        }

    }

    @Test
    void forceThreehashToEnd() {
        for (int i = 0; i < params.maxL; i++) {
            stack = Treehash.standardTreehash(new Node(0, publicKey[i], i), stack, params.bitmaskLTree);
        }
        Treehash.forceThreehashToEnd(stack, params.bitmaskLTree);
        assertEquals(stack.size(), 1);
        assertEquals(stack.peek().height, HelperFunctions.ceilLogTwo(params.maxL));
        assertEquals(stack.peek().value.length, params.n);
        assertEquals(stack.peek().index, 0);

        int size = params.upperSize;
        publicKey = new byte[size][params.n];
        stack = new Stack<Node>();
        for (int i = 0; i < size; i++)
            HelperFunctions.fillBytesRandomly(publicKey[i]);
        for (int i = 0; i < size; i++) {
            stack = Treehash.standardTreehash(new Node(0, publicKey[i], i), stack, params.bitmaskMain);
        }
        Treehash.forceThreehashToEnd(stack, params.bitmaskMain);
        assertEquals(stack.size(), 1);
        assertEquals(stack.peek().height, params.upperH);
        assertEquals(stack.peek().value.length, params.n);
        assertEquals(stack.peek().index, 0);
    }

    @Test
    void treeHashInstance() {
        Treehash treehash = new Treehash(new Stack<Node>(), params.upperH, params.bitmaskMain, params.bitmaskLTree, params.n, params.lU, params.X, params.wU);
        treehash.initialize(params.seed, 0);
        int size = params.upperSize;
        for (int i = 0; i < size; i++)
            treehash.update();

        assertEquals(treehash.stack.size(), 0);
        assertEquals(treehash.node.height, params.upperH);
        assertEquals(treehash.node.value.length, params.n);
        assertEquals(treehash.node.index, 0);

        treehash = new Treehash(new Stack<Node>(), 3, params.bitmaskMain, params.bitmaskLTree, params.n, params.lU, params.X, params.wU);
        treehash.initialize(params.seed, 8);
        size = (int) Math.pow(2, 3);
        for (int i = 0; i < size; i++)
            treehash.update();

        assertEquals(treehash.stack.size(), 0);
        assertEquals(treehash.node.height, 3);
        assertEquals(treehash.node.value.length, params.n);
        assertEquals(treehash.node.index, 1);
    }
}