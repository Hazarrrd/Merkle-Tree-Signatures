package com.signature.scheme.tools;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashFunctionTest {

    @Test
    void computeHash() {
        HelperFunctions.setHashFuncton(32);
        byte[] array = new byte[64];
        byte[] array2 = new byte[64];
        boolean bool = true;
        HelperFunctions.fillBytesRandomly(array);
        byte[] arrayOutput = HashFunction.computeHash(array);
        byte[] arrayOutput2 = HashFunction.computeHash(array);
        byte[] arrayOutput3 = HashFunction.computeHash(array2);
        assertEquals(arrayOutput.length,arrayOutput2.length);
        assertEquals(arrayOutput.length,32);
        for(int i=0;i<arrayOutput.length;i++){
            if(arrayOutput[i] != arrayOutput2[i]){
                bool = false;
            }
        }
        assertEquals(bool,true);
        for(int i=0;i<arrayOutput.length;i++){
            if(arrayOutput[i] != arrayOutput3[i]){
                bool = false;
            }
        }
        assertEquals(bool,false);
    }
}