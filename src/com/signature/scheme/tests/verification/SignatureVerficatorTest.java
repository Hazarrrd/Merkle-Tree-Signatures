package com.signature.scheme.tests.verification;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.keys.KeysKeeper;
import com.signature.scheme.signing.Signature;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.verfication.SignatureVerficator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureVerficatorTest {

    @Test
    void verifySignature() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params);
        keysKeeper.generateKeys();
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey, keysKeeper.params);
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        Signature signature1 = signatureGenerator.signMessage("TEST");
        Signature signature2 = signatureGenerator.signMessage("TEST");
        Signature signature3 = signatureGenerator.signMessage("TESTt");

        KeysKeeper keysKeeper2 = new KeysKeeper(params);
        keysKeeper2.generateKeys();
        SignatureGenerator signatureGenerator2 = new SignatureGenerator(keysKeeper2);
        Signature signature4 = signatureGenerator2.signMessage("TEST");

        assertEquals(signatureVerficator.verifySignature(signature1, "TEST"), true);
        assertEquals(signatureVerficator.verifySignature(signature1, "TESTt"), false);
        assertEquals(signatureVerficator.verifySignature(signature2, "TEST"), true);
        assertEquals(signatureVerficator.verifySignature(signature3, "TEST"), false);
        assertEquals(signatureVerficator.verifySignature(signature4, "TEST"), false);
        int size = 10000;
        Signature[] signatures = new Signature[size];
        System.out.println("Key Generated");
        for (int i = 0; i < size - 3; i++) {
            signatures[i] = signatureGenerator.signMessage("TESTtt" + i);
        }
        System.out.println("Signature Generated");
        for (int i = 0; i < size - 3; i++) {
            assertEquals(signatureVerficator.verifySignature(signatures[i], "TESTtt" + i), true);
        }

    }

    @Test
    void verifySignatureWithMultipleStructures() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params);
        keysKeeper.generateKeys();
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey, keysKeeper.params);
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        int size = 10000;
        Signature[] signatures = new Signature[size];
        System.out.println("Key Generated to sign :  " + size);
        for (int i = 0; i < size; i++) {
            signatures[i] = signatureGenerator.signMessage("TESTtt" + i);
        }
        System.out.println("Signature Generated");
        for (int i = 0; i < size; i++) {
            assertEquals(signatureVerficator.verifySignature(signatures[i], "TESTtt" + i), true);
        }
    }
}