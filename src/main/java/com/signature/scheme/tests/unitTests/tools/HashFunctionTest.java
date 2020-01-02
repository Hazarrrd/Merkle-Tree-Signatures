package com.signature.scheme.tests.unitTests.tools;

import com.signature.scheme.algorithm.tools.HashFunction;
import com.signature.scheme.algorithm.tools.HelperFunctions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class HashFunctionTest {

    @Test
    void computeHash() {
        byte[] key = new byte[32];
        byte[] array = new byte[64];
        byte[] array2 = new byte[64];
        boolean bool = true;
        HelperFunctions.fillBytesRandomly(key);
        HelperFunctions.fillBytesRandomly(array);
        HashFunction.setFunction(key, 32);
        byte[] arrayOutput = HashFunction.computeHash(array);
        byte[] arrayOutput2 = HashFunction.computeHash(array);
        byte[] arrayOutput3 = HashFunction.computeHash(array2);
        assertEquals(arrayOutput.length, arrayOutput2.length);
        assertEquals(arrayOutput.length, 32);
        for (int i = 0; i < arrayOutput.length; i++) {
            if (arrayOutput[i] != arrayOutput2[i]) {
                bool = false;
            }
        }
        assertEquals(bool, true);
        for (int i = 0; i < arrayOutput.length; i++) {
            if (arrayOutput[i] != arrayOutput3[i]) {
                bool = false;
            }
        }
        assertEquals(bool, false);
    }

    @Test
    void setHashFuncton() {
        byte[] array = new byte[32];
        HelperFunctions.fillBytesRandomly(array);
        HashFunction.setFunction(array, 32);
        Assertions.assertEquals(HashFunction.n, 32);
        assertNotNull(HashFunction.k);
        HashFunction.setFunction(array, 64);
        assertEquals(HashFunction.n, 64);
        assertNotNull(HashFunction.k);
    }
}