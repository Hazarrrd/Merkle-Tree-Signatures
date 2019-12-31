package com.signature.scheme.algorithm.tools.ASN1;

import com.signature.scheme.algorithm.merkleTree.Node;
import com.signature.scheme.algorithm.signing.StructureSignature;
import org.bouncycastle.asn1.*;

import java.util.ArrayList;

public class ASN1Signature extends ASN1Object {

    private ASN1Encodable[] asn1Array;


    public ASN1Signature(Node[] upperAuthPath, byte[][] lowerTreeSignature, Node[] lowerAuthPath, byte[][] msgSignature, int index, int treeIndex, ArrayList<StructureSignature> structureSignatures) {

        ArrayList<ASN1Encodable> asn1List = new ArrayList<ASN1Encodable>();

        asn1List.add(new ASN1Integer(index));
        asn1List.add(new ASN1Integer(treeIndex));

        for (int i = 0; i < upperAuthPath.length; i++) {
            asn1List.add(new ASN1Node(upperAuthPath[i]));
        }

        for (int i = 0; i < lowerTreeSignature.length; i++) {
            asn1List.add(new BEROctetString(lowerTreeSignature[i]));
        }

        for (int i = 0; i < lowerAuthPath.length; i++) {
            asn1List.add(new ASN1Node(lowerAuthPath[i]));
        }

        for (int i = 0; i < msgSignature.length; i++) {
            asn1List.add(new BEROctetString(msgSignature[i]));
        }


        for (int i = 0; i < structureSignatures.size(); i++) {
            asn1List.add(new ASN1StructureSignature(structureSignatures.get(i)));
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