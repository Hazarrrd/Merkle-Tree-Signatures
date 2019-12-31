package com.signature.scheme.algorithm.tools.ASN1;

import com.signature.scheme.algorithm.merkleTree.Node;
import com.signature.scheme.algorithm.signing.StructureSignature;
import org.bouncycastle.asn1.*;

import java.util.ArrayList;

public class ASN1StructureSignature extends ASN1Object {

    private ASN1Encodable[] asn1Array;

    public ASN1StructureSignature(StructureSignature structureSignature) {
        //nextStructSignature byte[][] ; oldStructAuthPath Node[]
        ArrayList<ASN1Encodable> asn1List = new ArrayList<ASN1Encodable>();

        byte[][] nextStructSignature = structureSignature.nextStructSignature;
        for (int i = 0; i < nextStructSignature.length; i++) {
            asn1List.add(new BEROctetString(nextStructSignature[i]));
        }

        Node[] authPath = structureSignature.oldStructAuthPath;
        for (int i = 0; i < authPath.length; i++) {
            asn1List.add(new ASN1Node(authPath[i]));
        }

        asn1Array = new ASN1Encodable[asn1List.size()];
        asn1Array = asn1List.toArray(asn1Array);

    }

    // returns a DERSequence containing all the fields
    @Override
    public ASN1Primitive toASN1Primitive() {
        return new BERSequence(asn1Array);
    }
}