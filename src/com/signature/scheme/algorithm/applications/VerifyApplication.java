package com.signature.scheme.algorithm.applications;

import com.signature.scheme.algorithm.keys.PublicKey;
import com.signature.scheme.algorithm.signing.Signature;
import com.signature.scheme.algorithm.tools.FileWriteReadHelper;
import com.signature.scheme.algorithm.verfication.SignatureVerficator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Scanner;

/**
 * Application that verify digital signatures
 */
public class VerifyApplication {
    private SignatureVerficator signatureVerficator;

    public VerifyApplication(String path) {
        signatureVerficator = new SignatureVerficator(loadPublicKey(path + "/publicKey.txt")
                , FileWriteReadHelper.loadParams(path));
    }

    public static void main(String[] args) {
        startVerifyApp();
    }

    public static void startVerifyApp() {
        //String path = "/home/janek/IdeaProjects/MerkleSignatures/appData";
        Scanner input = new Scanner(System.in);
        System.out.println("Podaj ścieżkę do folderu, w którym znajdują się pliki: publicKey.txt, params.txt oraz podpisy cyfrowe");
        String path = input.nextLine();
        VerifyApplication verifyApplication = new VerifyApplication(path);
        while (true) {
            System.out.println("Podaj numer folderu, zawierającego wiadomość i podpis cyfrowy do weryfikacji");
            int signatureNumber = input.nextInt();
            String pathToSignature = path + "/signedMsg" + signatureNumber;
            verifyApplication.verify(pathToSignature);
        }
    }

    public void verify(String pathToSignature) {
        Signature signature = loadSignature(pathToSignature);
        // String msg = FileWriteReadHelper.loadMsg(pathToSignature, "/msg.txt");
        String msg = FileWriteReadHelper.fileToString(pathToSignature + "/msg.txt");
        Boolean valid = signatureVerficator.verifySignature(signature, msg);
        if (valid == true) {
            System.out.println("PODPIS JEST PRAWIDŁOWY");
        } else {
            System.out.println("ERROR - PODPIS NIE JEST PRAWIDŁOWY");
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
