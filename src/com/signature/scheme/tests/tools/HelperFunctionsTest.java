package com.signature.scheme.tests.tools;

import com.signature.scheme.merkleTree.Node;
import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.HelperFunctions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Stack;

import static org.junit.jupiter.api.Assertions.*;

class HelperFunctionsTest {

    @Test
    void intToByteArray() {
        byte[] array = HelperFunctions.intToByteArray(6, 5);
        assertEquals(5, array.length);
        assertEquals(0, array[0]);
        assertEquals(0, array[1]);
        assertEquals(0, array[2]);
        assertEquals(0, array[3]);
        assertEquals(6, array[4]);
        //System.out.println(array[0] + " " + array[1]);
        // 6 -> 110
        byte[] array2 = HelperFunctions.intToByteArray(6, 5);
        assertEquals(5, array2.length);
        assertEquals(0, array2[0]);
        assertEquals(0, array2[1]);
        assertEquals(0, array2[2]);
        assertEquals(0, array2[3]);
        assertEquals(6, array2[4]);
        byte[] array3 = HelperFunctions.intToByteArray(300, 5);
        assertEquals(5, array3.length);
        assertEquals(0, array3[0]);
        assertEquals(0, array3[1]);
        assertEquals(0, array3[2]);
        assertEquals(1, array3[3]);
        assertEquals(44, array3[4]);
    }

    @Test
    void fromByteArray() {
        byte[] array = HelperFunctions.intToByteArray(6, 7);
        int a = HelperFunctions.fromByteArray(array);
        assertEquals(6, a);
        array = HelperFunctions.intToByteArray(6, 9);
        a = HelperFunctions.fromByteArray(array);
        assertEquals(6, a);
        byte[] array2 = {1, 0, 1, 1};
        a = HelperFunctions.fromByteArray(array2);
        assertEquals(11, a);

        byte[] array3 = {0, 1, 0, 1, 1};
        a = HelperFunctions.fromByteArray(array3);
        assertEquals(11, a);

        byte[] array4 = {63};
        a = HelperFunctions.fromByteArray(array4);
        assertEquals(63, 63);
        /*
        byte [] array5 = {63,1};
        a = HelperFunctions.fromByteArray(array5);
        System.out.println(a);
        assertEquals(190, a);*/
    }

    @Test
    void ceilLogTwo() {
        assertEquals(HelperFunctions.ceilLogTwo(8), 3);
        assertEquals(HelperFunctions.ceilLogTwo(9), 4);
        assertEquals(HelperFunctions.ceilLogTwo(15), 4);
        assertNotEquals(HelperFunctions.ceilLogTwo(16), 5);
    }

    @Test
    void setHashFuncton() {
        HelperFunctions.setHashFuncton(5);
        Assertions.assertEquals(HashFunction.n, 5);
        assertNotNull(HashFunction.k);
        HelperFunctions.setHashFuncton(6);
        assertEquals(HashFunction.n, 6);
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
        for (int i = 0; i < k; i++) {
            // System.out.println("a) " + array[i] + " b) " + array2[i]);
            if (array[i] != array2[i])
                bool = true;
        }
        assertEquals(bool, true);
    }

    @Test
    void xorTwoByteArrays() {

        byte[] array1 = {1, 0, 1, 1, 0, 9};
        byte[] array2 = {1, 1, 0, 0, 0, 4};
        byte[] array3 = HelperFunctions.xorTwoByteArrays(array1, array2);
      /*  for (int i = 0;i<array3.length;i++){
            System.out.println("a) " + array1[i] + " b) " + array2[i] + "c) " + array3[i]);
        }*/
        assertEquals(array3[0], 0);
        assertEquals(array3[1], 1);
        assertEquals(array3[2], 1);
        assertEquals(array3[3], 1);
        assertEquals(array3[4], 0);
        assertEquals(array3[5], 13);

        array1 = new byte[5];
        array2 = new byte[5];
        array3 = new byte[5];
        HelperFunctions.fillBytesRandomly(array1);
        HelperFunctions.fillBytesRandomly(array2);
        array3 = HelperFunctions.xorTwoByteArrays(array1, array2);
       /* for (int i = 0;i<array3.length;i++){
            System.out.println("a) " + array1[i] + " b) " + array2[i] + " c) " + array3[i]);
        }*/

    }

    @Test
    void log2() {
        assertEquals(HelperFunctions.log2(8), 3);
        assertEquals(HelperFunctions.log2(4), 2);
        assertEquals(HelperFunctions.log2(16), 4);
        assertNotEquals(HelperFunctions.log2(9), 8);
        assertNotEquals(HelperFunctions.log2(9), 10);
    }

    @Test
    void reverseStack() {
        Stack<Node> stack = new Stack();
        byte[] array = new byte[5];
        stack.push(new Node(0, array, 1));
        stack.push(new Node(0, array, 2));
        stack.push(new Node(0, array, 3));
        stack.push(new Node(0, array, 4));
        stack.push(new Node(0, array, 5));
        Stack<Node>[] stackArray = new Stack[5];
        stackArray[1] = stack;
        stackArray[0] = new Stack<Node>();
        stackArray[2] = new Stack<Node>();
        stackArray[3] = new Stack<Node>();
        stackArray[4] = new Stack<Node>();

        assertEquals(stackArray[1].pop().index, 5);
        HelperFunctions.reverseStack(stackArray);
        assertEquals(stackArray[1].pop().index, 1);
        assertEquals(stackArray[1].pop().index, 2);
        assertEquals(stackArray[1].pop().index, 3);

    }

    @Test
    void msgDigest(){
        String msg1 = "msgTest";
        String msg2 = "msgTest2";
        String msg3 = "msgTest";
        byte[] hash1 = HelperFunctions.messageDigestSHA3_256(msg1);
        byte[] hash2 = HelperFunctions.messageDigestSHA3_256(msg2);
        byte[] hash3 = HelperFunctions.messageDigestSHA3_256(msg3);
        assertEquals(hash1.length,32);
        assertEquals(hash2.length,32);
        assertEquals(hash3.length,32);
        assertArrayEquals(hash1,hash3);
        Boolean bool = false;
        for(int i = 0;i<hash1.length;i++){
            if(hash1[i]!=hash2[i]){
                bool = true;
                break;
            }
        }
        assertEquals(bool,true);

    }

    @Test
    void byteArrayToBinaryString(){
        byte[] array = {1,2,3};
        String string = HelperFunctions.byteArrayToBinaryString(array);
        assertEquals("000000010000001000000011",string);
    }
}