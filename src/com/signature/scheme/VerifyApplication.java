package com.signature.scheme;

import com.signature.scheme.keys.PublicKey;
import com.signature.scheme.signing.Signature;
import com.signature.scheme.tools.FileWriteReadHelper;
import com.signature.scheme.verfication.SignatureVerficator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * Application that verify digital signatures
 */
public class VerifyApplication {
    private SignatureVerficator signatureVerficator;

    public VerifyApplication(String path) {
        signatureVerficator = new SignatureVerficator(loadPublicKey(path + "/publicKey.txt")
                , FileWriteReadHelper.loadParams(path));
    }

    public void verify(String pathToSignature) {
        Signature signature = loadSignature(pathToSignature);
        String msg = FileWriteReadHelper.loadMsg(pathToSignature, "/msg.txt");
        Boolean valid = signatureVerficator.verifySignature(signature, msg);
        if (valid == true) {
            System.out.println("SIGNATURE IS VALID");
        } else {
            System.out.println("ERROR - SIGATURE IS INVALID");
        }

    }

    public static PublicKey loadPublicKey(String path) {
        File file = new File(path);

        try {

            FileInputStream fi = new FileInputStream(file);
            ObjectInputStream oi = new ObjectInputStream(fi);
            try {
                return (PublicKey) oi.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static Signature loadSignature(String path) {
        File file = new File(path + "/signature.txt");

        try {

            FileInputStream fi = new FileInputStream(file);
            ObjectInputStream oi = new ObjectInputStream(fi);
            try {
                return (Signature) oi.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
