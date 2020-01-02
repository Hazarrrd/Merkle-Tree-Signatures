package com.signature.scheme.algorithm.tools.ASN1;

import org.bouncycastle.asn1.*;

import java.util.ArrayList;

public class ASN1PublicKey extends ASN1Object {

    private ASN1Encodable[] asn1Array;


    public ASN1PublicKey(byte[][] bitmaskLTree, byte[][] bitmaskMain, byte[] x, byte[] upperRoot) {


        ArrayList<ASN1Encodable> asn1List = new ArrayList<ASN1Encodable>();
        for (int i = 0; i < bitmaskLTree.length; i++) {
            asn1List.add(new BEROctetString(bitmaskLTree[i]));
        }
        for (int i = 0; i < bitmaskMain.length; i++) {
            asn1List.add(new BEROctetString(bitmaskMain[i]));
        }

        asn1List.add(new BEROctetString(x));
        asn1List.add(new BEROctetString(upperRoot));

        asn1Array = new ASN1Encodable[asn1List.size()];
        asn1Array = asn1List.toArray(asn1Array);
    }

    // returns a DERSequence containing all the fields
    @Override
    public ASN1Primitive toASN1Primitive() {
        return new BERSequence(asn1Array);
    }
}
