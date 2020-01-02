package com.signature.scheme.tests.unitTests.keys;

import com.signature.scheme.algorithm.keys.KeysKeeper;
import com.signature.scheme.algorithm.keys.ParametersBase;
import com.signature.scheme.algorithm.keys.PrivateKey;
import com.signature.scheme.algorithm.keys.PublicKey;
import com.signature.scheme.algorithm.merkleTree.Node;
import com.signature.scheme.algorithm.merkleTree.Treehash;
import com.signature.scheme.algorithm.tools.FSGenerator;
import com.signature.scheme.algorithm.tools.HashFunction;
import com.signature.scheme.algorithm.tools.HelperFunctions;
import com.signature.scheme.algorithm.tools.PseudorndFunction;
import org.junit.jupiter.api.Test;

import java.util.Stack;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeysKeeperTest {

    @Test
    void generateKeys() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m, params.n, params.kU, params.kL, params.upperH, params.lowerH, params.wL, params.wU, params.treeGrowth);
        keysKeeper.generateKeys();
        assertEquals(keysKeeper.privateKey.lowerSignature.upperAuthPath.length, params.upperH);
        assertEquals(keysKeeper.privateKey.lowerSignature.treeIndex, 0);
        assertEquals(keysKeeper.privateKey.lowerSignature.lowerTreeSignature[0].length, params.n);
    }

    @Test
    void generateTrees() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m, params.n, params.kU, params.kL, params.upperH, params.lowerH, params.wL, params.wU, params.treeGrowth);
        keysKeeper.privateKey = new PrivateKey();
        keysKeeper.publicKey = new PublicKey();
        keysKeeper.publicKey.bitmaskMain = keysKeeper.params.bitmaskMain;
        keysKeeper.publicKey.bitmaskLTree = keysKeeper.params.bitmaskLTree;
        keysKeeper.publicKey.X = keysKeeper.params.X;
        byte[] root = keysKeeper.generateTrees();
        assertEquals(root.length, params.n);
        PrivateKey privateKey = keysKeeper.privateKey;
        PublicKey publicKey = keysKeeper.publicKey;
        assertEquals(publicKey.X.length, params.n);
        assertEquals(publicKey.bitmaskLTree.length, HelperFunctions.ceilLogTwo(params.maxL));
        assertEquals(publicKey.bitmaskMain.length, params.maxH);
        assertEquals(publicKey.upperRoot.length, params.n);
        assertEquals(privateKey.lowerGenState.length, params.n);
        assertEquals(privateKey.upperGenState.length, params.n);
        assertEquals(privateKey.nextGenState.length, params.n);
        assertEquals(privateKey.lowerPathComputation.leafIndex, 0);
        assertEquals(privateKey.lowerPathComputation.auth.length, params.lowerH);
        assertEquals(privateKey.upperPathComputation.leafIndex, 0);
        assertEquals(privateKey.upperPathComputation.auth.length, params.upperH);

    }

    @Test
    void generateRootOfTree() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m, params.n, params.kU, params.kL, params.upperH, params.lowerH, params.wL, params.wU, params.treeGrowth);
        HashFunction.setFunction(params.hashFunctionKey, params.n);

        Node[] auth = new Node[params.upperH];
        Treehash[] treeHashArray = new Treehash[params.upperH - params.kU];
        Stack<Node>[] retain = new Stack[params.upperH - 1];
        for (int i = params.upperH - params.kU; i < retain.length; i++)
            retain[i] = new Stack<Node>();
        for (int i = 0; i < treeHashArray.length; i++) {
            treeHashArray[i] = new Treehash(new Stack<Node>(), i, params.bitmaskMain, params.bitmaskLTree, params.n, params.lU, params.X, params.wU);
        }
        FSGenerator upperGenerator = new FSGenerator(new PseudorndFunction(params.n), new PseudorndFunction(params.n), params.seed);

        keysKeeper.privateKey = new PrivateKey();
        keysKeeper.publicKey = new PublicKey();
        keysKeeper.publicKey.bitmaskMain = keysKeeper.params.bitmaskMain;
        keysKeeper.publicKey.bitmaskLTree = keysKeeper.params.bitmaskLTree;
        keysKeeper.publicKey.X = keysKeeper.params.X;

        keysKeeper.publicKey.upperRoot = keysKeeper.generateRootOfTree(upperGenerator, params.lU, params.wU, auth, treeHashArray, retain, params.upperH, params.kU, params.n);

        assertEquals(keysKeeper.publicKey.upperRoot.length, params.n);
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
}