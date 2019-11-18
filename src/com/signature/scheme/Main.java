package com.signature.scheme;

import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.verfication.SignatureVerficator;

public class Main {

    public static void main(String[] args) {
        KeysKeeper keysKeeper = new KeysKeeper(32,32,4,4,10,10,8,8);
        keysKeeper.generateKeys();
        HelperFunctions.setHashFuncton(keysKeeper.params.n);
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey,keysKeeper.params);
        byte[] m = new byte[100];
        HelperFunctions.fillBytesRandomly(m);
        String msg = "TestingMsg";
        Signature signature = signatureGenerator.signMessage(msg);
        Boolean isValid = signatureVerficator.verifySignature(signature,msg);
        if(isValid){
            System.out.println("SIGNATURE IS FINE");
        } else {
            System.out.println("SIGNATURE IS FALSED");
        }


    }


}
