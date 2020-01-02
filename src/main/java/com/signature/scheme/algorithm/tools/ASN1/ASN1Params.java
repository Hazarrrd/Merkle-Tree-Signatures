package com.signature.scheme.algorithm.tools.ASN1;

import com.signature.scheme.algorithm.keys.ParametersBase;
import org.bouncycastle.asn1.*;

public class ASN1Params extends ASN1Object {

    private ASN1Encodable[] asn1Array;


    public ASN1Params(ParametersBase paramsToSend) {
        asn1Array = new ASN1Encodable[8];
        asn1Array[0] = new ASN1Integer(paramsToSend.m);
        asn1Array[1] = new ASN1Integer(paramsToSend.n);
        asn1Array[2] = new ASN1Integer(paramsToSend.upperH);
        asn1Array[3] = new ASN1Integer(paramsToSend.lowerH);
        asn1Array[4] = new ASN1Integer(paramsToSend.wU);
        asn1Array[5] = new ASN1Integer(paramsToSend.wL);
        asn1Array[6] = new ASN1Integer(paramsToSend.treeGrowth);
        asn1Array[7] = new BEROctetString(paramsToSend.hashFunctionKey);
    }

    // returns a DERSequence containing all the fields
    @Override
    public ASN1Primitive toASN1Primitive() {
        return new BERSequence(asn1Array);
    }
}