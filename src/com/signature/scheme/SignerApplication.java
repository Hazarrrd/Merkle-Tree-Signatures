package com.signature.scheme;

import com.signature.scheme.keys.KeysKeeper;
import com.signature.scheme.keys.PublicKey;
import com.signature.scheme.signing.Signature;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.tools.FileWriteReadHelper;

import java.io.*;


public class SignerApplication {
    private SignatureGenerator signatureGenerator;
    private int counter;
    private String path;

    public SignerApplication(String path) {
        this.path = path;
        counter = 0;

        ParametersBase params = FileWriteReadHelper.loadParams(path);

        KeysKeeper keysKeeper = new KeysKeeper(params);
        keysKeeper.generateKeys();
        sendPublicKey(keysKeeper.publicKey, path);
        this.signatureGenerator = new SignatureGenerator(keysKeeper);
    }


    private void sendSignature(Signature signature, String path) {
        FileOutputStream outputStream = null;
        //"+signature.structureSignatures.size()+"_"+signature.treeIndex+"_"+signature.index+"
        File targetFile = new File(path + "/signedMsg" + counter + "/signature.txt");
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }
        try {
            outputStream = new FileOutputStream(path + "/signedMsg" + counter + "/signature.txt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            ObjectOutputStream objectOut = null;
            objectOut = new ObjectOutputStream(outputStream);
            objectOut.writeObject(signature);
            objectOut.close();
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void sendPublicKey(PublicKey publicKey, String path) {
        FileOutputStream outputStream = null;
        File targetFile = new File(path + "/publicKey.txt");
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }
        try {
            outputStream = new FileOutputStream(path + "/publicKey.txt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            ObjectOutputStream objectOut = null;
            objectOut = new ObjectOutputStream(outputStream);
            objectOut.writeObject(publicKey);
            objectOut.close();
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void signMsg() {
        String msg = FileWriteReadHelper.loadMsg(path, "/msgToSign.txt");

        Signature signature = signatureGenerator.signMessage(msg);
        sendSignature(signature, path);
        String file = "/signedMsg" + counter + "/msg.txt";
        FileWriteReadHelper.sendMsg(path, msg, file);
        counter++;
    }

}
