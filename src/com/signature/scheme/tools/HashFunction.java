package com.signature.scheme.tools;

import java.util.Arrays;

import static com.signature.scheme.tools.HelperFunctions.xorTwoByteArrays;

//second preimage
// {H_k : {0,1}^2n -> {0,1}^n | K belong to {0,1}^n }
public class HashFunction {
    public static int n;
    public static byte[] k;
    public static PseudorndFunction f;

    public static byte[] computeHash(byte[] input) {
        if (input.length != 2 * n) {
            System.err.println("Bad input to hash function (should be 2n)");
            return null;
        }
        byte[] a = Arrays.copyOfRange(input, 0, n);
        byte[] b = Arrays.copyOfRange(input, n, 2 * n);
        byte[] temp;
        f.setKey(k);
        temp = f.encrypt(a);
        f.setKey(xorTwoByteArrays(temp, a));
        temp = f.encrypt(b);
        return xorTwoByteArrays(temp, b);
    }

    public static void setFunction (byte[] hashKey,int outputSize){
            n = outputSize;
            f = new PseudorndFunction(n);
            k = hashKey;
    }

}
