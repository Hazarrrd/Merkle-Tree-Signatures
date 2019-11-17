package com.signature.scheme.tools;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PseudorndFunctionTest {

    @Test
    void setKey() {
        PseudorndFunction f = new PseudorndFunction(32);
        byte[] array = new byte[32];
        HelperFunctions.fillBytesRandomly(array);
        f.setKey(array);
    }

    @Test
    void encrypt() {
        int n=16;
        PseudorndFunction f = new PseudorndFunction(n);
        byte[] array = new byte[n];
        byte[] array2 = new byte[n];
        byte[] array3 = new byte[n];
        HelperFunctions.fillBytesRandomly(array);
        HelperFunctions.fillBytesRandomly(array2);
        f.setKey(array);
        array3 = f.encrypt(array2);
        assertEquals(n,array2.length);
        assertEquals(n,array.length);
        assertEquals(n,array3.length);
        boolean bool=false;
        bool = checkIfSame(array2, array3);
        assertEquals(false,bool);
    }

    @Test
    void composeFunction() {

        int n=16;
        PseudorndFunction f = new PseudorndFunction(n);
        byte[] array = new byte[n];
        byte[] array2 = new byte[n];
        byte[] array3 = new byte[n];
        byte[] array4 = new byte[n];
        HelperFunctions.fillBytesRandomly(array);
        HelperFunctions.fillBytesRandomly(array2);
        f.setKey(array);
        array3 = f.composeFunction(array2,array,5);
        array4 = f.composeFunction(array2,array,4);
        assertEquals(n,array2.length);
        assertEquals(n,array.length);
        assertEquals(n,array3.length);
        boolean bool=false;
        bool = checkIfSame(array2, array3);
        assertEquals(false,bool);
        bool = checkIfSame(array3, array4);
        assertEquals(false,bool);
        array4 = f.composeFunction(array2,array4,1);
        bool = checkIfSame(array4, array3);
        assertEquals(true,bool);
        array4 = f.composeFunction(array2,array4,1);
        bool = checkIfSame(array4, array3);
        assertEquals(false,bool);
    }

    @Test
    void decrypt() {
        int n=16;
        PseudorndFunction f = new PseudorndFunction(n);
        byte[] array = new byte[n];
        byte[] array2 = new byte[n];
        byte[] array3 = new byte[n];
        HelperFunctions.fillBytesRandomly(array);
        HelperFunctions.fillBytesRandomly(array2);
        f.setKey(array);
        array3 = f.encrypt(array2);
        assertEquals(n,array2.length);
        assertEquals(n,array.length);
        assertEquals(n,array3.length);
        boolean bool=true;
        bool = checkIfSame(array2, array3);
        assertEquals(false,bool);

        array3 = f.decrypt(array3);
        bool = checkIfSame(array2, array3);
        assertEquals(true,bool);

        array3 = f.encrypt(array3);
        array3 = f.encrypt(array3);
        bool = checkIfSame(array2, array3);
        assertEquals(false,bool);

        array3 = f.decrypt(array3);
        bool = checkIfSame(array2, array3);
        assertEquals(false,bool);

        array3 = f.decrypt(array3);
        bool = checkIfSame(array2, array3);
        assertEquals(true,bool);
    }

    private boolean checkIfSame(byte[] array2, byte[] array3) {
        Boolean bool = true;
        for (int i = 0; i < array2.length; i++) {
            if (array2[i] != array3[i]) {
                bool = false;
            }
        }
        return bool;
    }
}