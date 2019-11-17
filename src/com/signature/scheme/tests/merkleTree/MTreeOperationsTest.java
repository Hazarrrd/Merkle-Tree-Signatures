package com.signature.scheme.tests.merkleTree;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.merkleTree.MTreeOperations;
import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.HelperFunctions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class MTreeOperationsTest {

    ParametersBase param;

    @BeforeEach
    void setUp() {
        param = new ParametersBase();
    }

    @Test
    void testComputeParent() {
        byte[] array1 = new byte[param.n];
        byte[] array2 = new byte[param.n];
        byte[] array3 = new byte[2 * param.n];

        HelperFunctions.fillBytesRandomly(array1);
        HelperFunctions.fillBytesRandomly(array2);
        HelperFunctions.fillBytesRandomly(array3);

        Node a = new Node(0, array1, 2);
        Node b = new Node(0, array2, 3);
        Node c = MTreeOperations.computeParent(a, b, array3);
        assertEquals(1, c.height);
        assertEquals(1, c.index);
        assertEquals(param.n, c.value.length);

        Node a2 = new Node(1, array1, 2);
        Node b2 = new Node(1, array2, 3);
        Node c2 = MTreeOperations.computeParent(a2, b2, array3);
        assertEquals(2, c2.height);
        assertEquals(1, c2.index);
        assertEquals(param.n, c2.value.length);
    }

    @Test
    void testLeafCalc1() {
        Node a = MTreeOperations.leafCalc(param.n, param.seed, param.lL, param.X, param.wL, param.bitmaskLTree,2);
        assertEquals(a.height, 0);
        assertNotNull(a.value);
        assertEquals(a.value.length, param.n);
        assertEquals(a.index, 2);

        a = MTreeOperations.leafCalc(param.n, param.seed, param.lL, param.X, param.wL, param.bitmaskLTree,0);
        assertEquals(a.height, 0);
        assertNotNull(a.value);
        assertEquals(a.value.length, param.n);
        assertEquals(a.index, 0);
    }

    @Test
    void testLeafCalc2() {
        byte[][] pKey = new byte[param.lL][param.n];
        for (int i = 0; i < param.lL; i++) {
            HelperFunctions.fillBytesRandomly(pKey[i]);
        }

        Node a = MTreeOperations.leafCalc(param.n, param.lL, pKey, param.bitmaskLTree,2);
        assertEquals(a.height, 0);
        assertNotNull(a.value);
        assertEquals(a.value.length, param.n);
        assertEquals(a.index, 2);

        a = MTreeOperations.leafCalc(param.n, param.lL, pKey, param.bitmaskLTree,0);
        assertEquals(a.height, 0);
        assertNotNull(a.value);
        assertEquals(a.value.length, param.n);
        assertEquals(a.index, 0);
    }
}