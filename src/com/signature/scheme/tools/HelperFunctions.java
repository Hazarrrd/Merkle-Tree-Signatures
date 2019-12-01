package com.signature.scheme.tools;

import com.signature.scheme.merkleTree.Node;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Stack;

public class HelperFunctions {

    //Nieoptymalnie, do naprawy BROOOOOKEN !!!!!
    public static byte[] intToByteArray(int number, int l) {
       /* int size = ceilLogTwo(l);
        byte[] array = new byte[size];
        for (int i = 0;i<size;i++){
            if ((number & (1 << i)) != 0){
                array[size - 1 - i] = 1;
            }
            else {
                array[size - 1 - i] = 0;
            }
        }
        return array;*/
        byte[] array = new byte[l];
        for (int i = 0; i < l; i++) {
            array[i] = 0;
        }
        if (l >= 1)
            array[l - 1] = (byte) number;
        if (l >= 2)
            array[l - 2] = (byte) (number >>> 8);
        if (l >= 3)
            array[l - 3] = (byte) (number >>> 16);
        if (l >= 4)
            array[l - 4] = (byte) (number >>> 24);

        return array;
    }

    //Nieoptymalnie, do naprawy BROOOOOKEN !!!!!
    public static int fromByteArray(byte[] bytes) {
        int result = 0;
        int size = bytes.length;
        int mult = (int) Math.pow(2, size - 1);
        for (int i = 0; i < size; i++) {
            result += mult * bytes[i];
            mult /= 2;
        }
        return result;
    }

    public static int ceilLogTwo(int number) {
        int counter = 0;
        int sum = 1;
        while (sum < number) {
            sum *= 2;
            counter++;
        }
        return counter;
    }

    //Maybe is this too strong ? TOEDIT!!! ZMIENIA MOOOOOODY
    public static void fillBytesRandomly(byte[] bytes) {
       /* try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }*/
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
       /* for(int i =0;i<bytes.length;i++){
            if(bytes[i]%2 == 0){
                bytes[i] = 1;
            } else{
                bytes[i] = 0;
            }
        }*/
    }

    public static byte[] xorTwoByteArrays(byte[] a, byte[] b) {
        int i = 0;
        byte[] output = new byte[a.length];
        for (byte j : a)
            output[i] = (byte) (j ^ b[i++]);
        return output;
    }

    public static byte[] messageDigestSHA3_256(String msg) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest.digest(msg.getBytes(StandardCharsets.UTF_8));
    }

    //POTENCJALNIE TRACI DOKLADNOSC
    public static double log2(int n) {
        return (Math.log(n) / Math.log(2));
    }

    public static void reverseStack(Stack<Node>[] stack) {
        Stack<Node>[] stackReversed = new Stack[stack.length];
        for (int h = 0; h < stack.length; h++) {
            if(stack[h]!= null) {
                stackReversed[h] = new Stack<Node>();
                int size = stack[h].size();
                for (int i = 0; i < size; i++)
                    stackReversed[h].push(stack[h].pop());
                stack[h] = stackReversed[h];
            }
        }
    }

    public static String stringPadding(int l, int wBytes, String msgBinaryString) {
       /* while (msgBinaryString.length() != l * wBytes) {
            msgBinaryString += "0";
        }*/
        while (msgBinaryString.length() < l * wBytes) {
            msgBinaryString += "0";
        }
        return msgBinaryString;
    }

    public static String byteArrayToBinaryString(byte[] byteArray) {
            char[] bits = new char[8 * byteArray.length];
            for(int i = 0; i < byteArray.length; i++) {
                byte temp = byteArray[i];
                int mask = 1;
                int byteNum = i * 8;
                for(int j = 7; j >= 0; j--) {
                    int bitValue = temp & mask;
                    if(bitValue == 0) {
                        bits[byteNum + j] = '0';
                    } else {
                        bits[byteNum + j] = '1';
                    }
                    mask <<= 1;
                }
            }
            return String.valueOf(bits);
    }

}
