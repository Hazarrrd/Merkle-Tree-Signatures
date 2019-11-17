package com.signature.scheme.merkleTree;

import com.signature.scheme.tools.HelperFunctions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MTreeOperationsTest {

    @org.junit.jupiter.api.Test
    void computeParent() {
        Node a = new Node(0, HelperFunctions.intToByteArray(5,5),2);
        Node b = new Node(0, HelperFunctions.intToByteArray(10,5),3);
        Node c = MTreeOperations.computeParent(a,b,HelperFunctions.intToByteArray(31,10));
        assertEquals(1, c.height);
        assertEquals(1, c.index);
        assertEquals(5, c.value.length);
    }

    @org.junit.jupiter.api.Test
    void leafCalc() {
    }

    @org.junit.jupiter.api.Test
    void testLeafCalc() {
    }

    @BeforeEach
    void setUp() {
    }

    @Test
    void testComputeParent() {
    }

    @Test
    void testLeafCalc1() {
    }

    @Test
    void testLeafCalc2() {
    }
}