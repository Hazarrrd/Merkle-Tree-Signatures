package com.signature.scheme;


import com.signature.scheme.tools.PseudorndFunction;

import static com.signature.scheme.tools.HelperFunctions.intToByteArray;

public class WOTSkeyGenerator {


    public static byte[] getPublicPart(byte[] x, int w, PseudorndFunction f, byte[] privatePart) {
        return f.composeFunction(x, privatePart, w - 1);
    }

    public static byte[] getPrivPart(int l, PseudorndFunction f, int i, byte[] seed) {
        f.setKey(seed);
        return f.encrypt(intToByteArray(i, f.n));
    }


}
