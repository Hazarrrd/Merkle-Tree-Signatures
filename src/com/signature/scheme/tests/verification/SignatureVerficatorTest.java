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
        KeysKeeper keysKeeper = new KeysKeeper(params.m,params.n,params.kU,params.kL,params.upperH,params.lowerH,params.wL,params.wU);
        keysKeeper.generateKeys();
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey,params);
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        Signature signature1 = signatureGenerator.signMessage("Wiadomosc");
        Signature signature2 = signatureGenerator.signMessage("Wiadomosc");
        Signature signature3 = signatureGenerator.signMessage("Wiadomoscc");

        KeysKeeper keysKeeper2 = new KeysKeeper(params.m,params.n,params.kU,params.kL,params.upperH,params.lowerH,params.wL,params.wU);
        keysKeeper2.generateKeys();
        SignatureGenerator signatureGenerator2 = new SignatureGenerator(keysKeeper);
        Signature signature4 = signatureGenerator2.signMessage("Wiadomosc");

        assertEquals(signatureVerficator.verifySignature(signature1,"Wiadomosc"),true);
        assertEquals(signatureVerficator.verifySignature(signature2,"Wiadomosc"),true);
        assertEquals(signatureVerficator.verifySignature(signature3,"Wiadomosc"),false);
        assertEquals(signatureVerficator.verifySignature(signature4,"Wiadomosc"),false);
    }
}