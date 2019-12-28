package com.signature.scheme.algorithm.applications;

import com.signature.scheme.algorithm.keys.KeysKeeper;
import com.signature.scheme.algorithm.keys.ParametersBase;
import com.signature.scheme.algorithm.keys.PublicKey;
import com.signature.scheme.algorithm.signing.Signature;
import com.signature.scheme.algorithm.signing.SignatureGenerator;
import com.signature.scheme.algorithm.tools.FileWriteReadHelper;

import java.io.*;
import java.util.Scanner;

/**
 * Application that signs messages
 */
public class SignerApplication {
    private SignatureGenerator signatureGenerator;
    private int signatureCounter;
    private String path;

    public static void main(String[] args) {
        startSignatureApp();
    }

    public static void startSignatureApp() {
        //  String path = "/home/janek/IdeaProjects/MerkleSignatures/appData";
        Scanner input = new Scanner(System.in);
        System.out.println("Podaj ścieżkę do miejsca w pamięci, w którym mają zostać zapisane pliki: publicKey.txt, params.txt oraz podpisy cyfrowe");
        String path = input.nextLine();

        System.out.println("Czy chcesz podać własne prarametry algorytmu ('T'-własne parametry/INACZEJ-domyślne parametry)");
        Boolean ownParams;
        switch (input.nextLine()) {
            case "T":
                ownParams = true;
                break;
            default:
                ownParams = false;
                break;
        }
        ParametersBase params;
        if (!ownParams) {
            params = new ParametersBase(32, 16, 4, 4, 6, 7, 8, 8, KeysKeeper.generateX(16), 1);
        } else {
            System.out.println("Podaj parametry (liczby naturalne) w następującej kolejności :K_up K_low H_up H_low W_l W_u treeGrowth \n" +
                    "K_up -> współczynnik K dla górnego drzewa \n" +
                    "K_low -> współczynnik K dla dolnych drzew \n" +
                    "H_up -> wysokość górnego drzewa \n" +
                    "H_low -> wysokość pierwszego dolnego drzewa \n" +
                    "W_up -> współczynnik W (Winternitza) dla górnego drzewa \n" +
                    "W_low -> współczynnik W (Winternitza) dla dolnych drzew \n" +
                    "treeGrowth -> 0 aby wybrać schemat XMSS+, 1 aby wybrać schemat rosnących dolnych drzew \n" +
                    "Pamiętaj, że musi być spełnione : H-K-2 mod 2 == 0");
            params = new ParametersBase(32, 16, input.nextInt(), input.nextInt(), input.nextInt(), input.nextInt(), input.nextInt(), input.nextInt(), KeysKeeper.generateX(16), input.nextInt());
            input.nextLine();
        }
        FileWriteReadHelper.sendParams(params, path);
        SignerApplication signerApplication = new SignerApplication(path);

        while (true) {
            System.out.println("Podaj ścieżkę do pliku .txt, dla którego zawartości ma zostać wygenerowany podpis cyfrowy");
            String pathToMsgFile = input.nextLine();
            System.out.println(pathToMsgFile);
            String msg = FileWriteReadHelper.fileToString(pathToMsgFile);
            signerApplication.signMsg(msg);
            System.out.println("Podpis cyfrowy został wygenerowany");
        }
    }

    public SignerApplication(String path) {
        this.path = path;
        signatureCounter = 0;

        ParametersBase params = FileWriteReadHelper.loadParams(path);

        KeysKeeper keysKeeper = new KeysKeeper(params);
        keysKeeper.generateKeys();
        sendPublicKey(keysKeeper.publicKey, path);
        this.signatureGenerator = new SignatureGenerator(keysKeeper);
    }


    private void sendSignature(Signature signature, String path) {
        FileOutputStream outputStream = null;
        File targetFile = new File(path + "/signedMsg" + signatureCounter + "/signature.txt");
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }
        try {
            outputStream = new FileOutputStream(path + "/signedMsg" + signatureCounter + "/signature.txt");
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

    public void signMsg(String msg) {
        Signature signature = signatureGenerator.signMessage(msg);
        sendSignature(signature, path);
        String file = "/signedMsg" + signatureCounter + "/msg.txt";
        //FileWriteReadHelper.sendMsg(path, msg, file);
        try {
            FileWriteReadHelper.stringToFile(path + file, msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
        signatureCounter++;
    }

}
