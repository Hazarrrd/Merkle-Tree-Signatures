package com.signature.scheme.tools;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HelperFunctionsTest {

    @Test
    void intToByteArray() {
        byte[] array = HelperFunctions.intToByteArray(6,7);
        assertEquals(3, array.length);
        assertEquals(1, array[0]);
        assertEquals(1, array[1]);
        assertEquals(0, array[2]);
        //System.out.println(array[0] + " " + array[1]);
        // 6 -> 110
        byte[] array2 = HelperFunctions.intToByteArray(6,8);
        assertEquals(3, array2.length);
        assertEquals(1, array2[0]);
        assertEquals(1, array2[1]);
        assertEquals(0, array2[2]);
        byte[] array3 = HelperFunctions.intToByteArray(6,9);
        assertEquals(4, array3.length);
        assertEquals(0, array3[0]);
        assertEquals(1, array3[1]);
        assertEquals(1, array3[2]);
        assertEquals(0, array3[3]);
    }

    @Test
    void fromByteArray() {
        byte[] array = HelperFunctions.intToByteArray(6,7);
        int a = HelperFunctions.fromByteArray(array);
        assertEquals(6, a);
        array = HelperFunctions.intToByteArray(6,9);
        a = HelperFunctions.fromByteArray(array);
        assertEquals(6, a);
        byte[] array2 = {1,0,1,1};
        a = HelperFunctions.fromByteArray(array2);
        assertEquals(11, a);

        byte[] array3 = {0,1,0,1,1};
        a = HelperFunctions.fromByteArray(array3);
        assertEquals(11, a);
    }

    @Test
    void ceilLogTwo() {
        assertEquals(HelperFunctions.ceilLogTwo(8),3);
        assertEquals(HelperFunctions.ceilLogTwo(9),4);
        assertEquals(HelperFunctions.ceilLogTwo(15),4);
        assertNotEquals(HelperFunctions.ceilLogTwo(16),5);
    }

    @Test
    void setHashFuncton() {
        HelperFunctions.setHashFuncton(5);
        assertEquals(HashFunction.n,5);
        assertNotNull(HashFunction.k);
        HelperFunctions.setHashFuncton(6);
        assertEquals(HashFunction.n,6);
        assertNotNull(HashFunction.k);
    }

    @Test
    void fillBytesRandomly() {
        int k = 64;
        Boolean bool = false;
        byte[] array = new byte[k];
        byte[] array2 = new byte[k];
        HelperFunctions.fillBytesRandomly(array);
        HelperFunctions.fillBytesRandomly(array2);
        for (int i = 0;i<k;i++){
            //System.out.println("a) " + array[i] + " b) " + array2[i]);
            if(array[i]!=array2[i])
                bool = true;
        }
        assertEquals(bool,true);
    }

    @Test
    void xorTwoByteArrays() {
    }

    @Test
    void log2() {
    }

    @Test
    void reverseStack() {
    }
}