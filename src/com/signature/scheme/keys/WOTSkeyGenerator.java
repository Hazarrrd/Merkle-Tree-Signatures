package com.signature.scheme.keys;


import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;

import static com.signature.scheme.tools.HelperFunctions.intToByteArray;

/**
 * Class that holds WOTS key generation methods.
 */
public class WOTSkeyGenerator {

    //Computes single part of WOTS public key
    public static byte[] getPublicPart(byte[] x, int w, PseudorndFunction f, byte[] privatePart) {
        return f.composeFunction(x, privatePart, w - 1);
    }

    //Computes single part of WOTS private key
    public static byte[] getPrivPart(int l, PseudorndFunction f, int i, byte[] seed) {
        f.setKey(seed);
        return f.encrypt(intToByteArray(i, f.n));
    }

    //Computes whole WOTS public key from given msgDigest, msgSignature and algorthim parameters.
    public static byte[][] computeWOTSPublicKey(byte[] msgDigest, int l1, int l2, int w, byte[] x, byte[][] msgSignature) {
        int actualMsgIndex = 0;
        int wBytes = HelperFunctions.ceilLogTwo(w);
        int nextMsgIndex = wBytes;
        int msgPartBaseW;
        int controlSum = 0;
        PseudorndFunction f = new PseudorndFunction(x.length);

        byte[][] WOTSpublicKey = new byte[l1 + l2][f.n];

        String msgBinaryString = HelperFunctions.byteArrayToBinaryString(msgDigest);
        msgBinaryString = HelperFunctions.stringPadding(l1, wBytes, msgBinaryString);

        for (int i = 0; i < l1; i++) {
            msgPartBaseW = Integer.parseInt(msgBinaryString.substring(actualMsgIndex, nextMsgIndex), 2);
            controlSum += (w - 1 - msgPartBaseW);
            actualMsgIndex = nextMsgIndex;
            nextMsgIndex += wBytes;
            WOTSpublicKey[i] = f.composeFunction(x, msgSignature[i], w - 1 - msgPartBaseW);
        }

        actualMsgIndex = 0;
        nextMsgIndex = wBytes;
        String controlSumBinaryString = Integer.toBinaryString(controlSum);
        controlSumBinaryString = HelperFunctions.stringPadding(l2, wBytes, controlSumBinaryString);
        for (int i = 0; i < l2; i++) {
            msgPartBaseW = Integer.parseInt(controlSumBinaryString.substring(actualMsgIndex, nextMsgIndex), 2);
            actualMsgIndex = nextMsgIndex;
            nextMsgIndex += wBytes;
            WOTSpublicKey[l1 + i] = f.composeFunction(x, msgSignature[l1 + i], w - 1 - msgPartBaseW);
        }
        return WOTSpublicKey;
    }


}
