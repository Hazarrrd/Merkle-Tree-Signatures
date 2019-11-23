package com.signature.scheme.tests.verification;

import com.signature.scheme.KeysKeeper;
import com.signature.scheme.ParametersBase;
import com.signature.scheme.Signature;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.verfication.SignatureVerficator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignatureVerficatorTest {

    @Test
    void verifySignature() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params);
        keysKeeper.generateKeys();
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey,keysKeeper.params);
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        Signature signature1 = signatureGenerator.signMessage("TEST");
        Signature signature2 = signatureGenerator.signMessage("TEST");
        Signature signature3 = signatureGenerator.signMessage("TESTt");

        KeysKeeper keysKeeper2 = new KeysKeeper(params);
        keysKeeper2.generateKeys();
        SignatureGenerator signatureGenerator2 = new SignatureGenerator(keysKeeper2);
        Signature signature4 = signatureGenerator2.signMessage("TEST");

        assertEquals(signatureVerficator.verifySignature(signature1,"TEST"),true);
       // assertEquals(signatureVerficator.verifySignature(signature1,"TESTt"),false);
        assertEquals(signatureVerficator.verifySignature(signature2,"TEST"),true);
       // assertEquals(signatureVerficator.verifySignature(signature3,"TEST"),false);
       // assertEquals(signatureVerficator.verifySignature(signature4,"TEST"),false);
        int size = (int) Math.pow(2,params.lowerH);
        Signature[] signatures = new Signature[4*(size-2)];
        for(int i =0;i<4*(size-2);i++){
           signatures[i] = signatureGenerator.signMessage("TESTtt" + i);
        }

        for(int i =0;i<4*(size-2);i++){
           // System.out.println(i+3);
            assertEquals(signatureVerficator.verifySignature(signatures[i],"TESTtt" + i),true);
        }
    }
}