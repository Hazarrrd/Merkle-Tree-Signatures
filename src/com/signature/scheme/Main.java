package com.signature.scheme;

import com.signature.scheme.applications.SignerApplication;
import com.signature.scheme.applications.VerifyApplication;
import com.signature.scheme.keys.KeysKeeper;
import com.signature.scheme.tools.FileWriteReadHelper;


public class Main {

    public static void main(String[] args) {
        generateAndCheckSomeSignatures();
        String path = "/home/janek/IdeaProjects/MerkleSignatures/appData";
        VerifyApplication verifyApplication = new VerifyApplication(path);
        String pathToSignature = "/home/janek/IdeaProjects/MerkleSignatures/appData/signedMsg0";
        verifyApplication.verify(pathToSignature);
    }

    public static void generateAndCheckSomeSignatures() {
        String path = "/home/janek/IdeaProjects/MerkleSignatures/appData";
        String path2 = "/home/janek/IdeaProjects/MerkleSignatures/appDataTwo";
        ParametersBase params = new ParametersBase(32, 16, 4, 4, 6, 7, 8, 8, KeysKeeper.generateX(16), 1);
        FileWriteReadHelper.sendParams(params, path);
        FileWriteReadHelper.sendParams(params, path2);

        SignerApplication signerApplication = new SignerApplication(path);
        VerifyApplication verifyApplication = new VerifyApplication(path);

        SignerApplication signerApplication2 = new SignerApplication(path2);
        VerifyApplication verifyApplication2 = new VerifyApplication(path2);


        FileWriteReadHelper.sendMsg(path, "TESTOWA WIADOMOSC", "/msgToSign.txt");
        FileWriteReadHelper.sendMsg(path2, "TESTOWA WIADOMOSC", "/msgToSign.txt");
        signerApplication.signMsg();
        signerApplication2.signMsg();
        String pathToSignature = "/home/janek/IdeaProjects/MerkleSignatures/appData/signedMsg0";
        verifyApplication.verify(pathToSignature);
        verifyApplication2.verify(pathToSignature);

    }


}
