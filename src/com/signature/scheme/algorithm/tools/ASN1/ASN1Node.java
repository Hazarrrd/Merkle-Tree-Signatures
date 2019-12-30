package com.signature.scheme.algorithm.tools.ASN1;

import com.signature.scheme.algorithm.merkleTree.Node;
import org.bouncycastle.asn1.*;

public class ASN1Node extends ASN1Object {

    public BEROctetString value;
    public ASN1Integer index, height;


    public ASN1Node(Node node) {
        this.value = new BEROctetString(node.value);
        this.index = new ASN1Integer(node.index);
        this.height = new ASN1Integer(node.height);
    }

    // returns a DERSequence containing all the fields
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1Encodable[] v = new ASN1Encodable[]{this.height, this.value, this.index};
        return new BERSequence(v);
    }
}
