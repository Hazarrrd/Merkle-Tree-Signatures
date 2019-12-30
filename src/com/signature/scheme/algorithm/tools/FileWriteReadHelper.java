package com.signature.scheme.algorithm.tools;

import com.signature.scheme.algorithm.keys.ParametersBase;
import com.signature.scheme.algorithm.tools.ASN1.ASN1Params;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Class has helper functions, that allows to write/read data to/from files.
 */
public class FileWriteReadHelper {

    public static void writeToFile(byte[] data, OutputStream outputStream) {
        try {
            outputStream.write(data);
            String string = "\n";
            outputStream.write(string.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeToFile(int number, OutputStream outputStream) {
        try {
            String string = "" + number;
            string += "\n";
            byte[] data = string.getBytes();
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void writeToFile(String string, OutputStream outputStream) {
        try {
            string += "\n";
            byte[] data = string.getBytes();
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sendSerilizedParams(ParametersBase params, String path) {
        FileOutputStream outputStream = null;
        File targetFile = new File(path + "/params.txt");
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }
        try {
            outputStream = new FileOutputStream(path + "/params.txt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            ObjectOutputStream objectOut = null;
            objectOut = new ObjectOutputStream(outputStream);
            objectOut.writeObject(params);
            objectOut.close();
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void sendASN1Params(ParametersBase params, String path) {
        FileOutputStream outputStream = null;
        String pathToFile = path + "/params.txt";
        File targetFile = new File(pathToFile);
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }
        try {
            ParametersBase paramsToSend = new ParametersBase(params.m, params.n, params.upperH, params.lowerH, params.wU, params.wL, params.treeGrowth, params.hashFunctionKey);
            ASN1Params asn1Params = new ASN1Params(paramsToSend);
            String base64String = new String(Base64.encode(asn1Params.getEncoded()));
            FileWriteReadHelper.stringToFile(pathToFile, base64String);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sendMsg(String path, String msg, String fileName) {
        FileOutputStream outputStream = null;
        File targetFile = new File(path + fileName);
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }
        try {
            outputStream = new FileOutputStream(path + fileName);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            ObjectOutputStream objectOut = null;
            objectOut = new ObjectOutputStream(outputStream);
            objectOut.writeObject(msg);
            objectOut.close();
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String loadMsg(String path, String fileName) {
        File file = new File(path + fileName);

        try {

            FileInputStream fi = new FileInputStream(file);
            ObjectInputStream oi = new ObjectInputStream(fi);
            try {
                return (String) oi.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static ParametersBase loadSerializedParams(String path) {

        File file = new File(path + "/params.txt");


        try {
            FileInputStream fi = new FileInputStream(file);
            ObjectInputStream oi = new ObjectInputStream(fi);
            try {
                return (ParametersBase) oi.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            System.out.println("Niepoprawna ścieżka lub uszkodzone pliki - kończenie pracy aplikacji");
            System.exit(64);
        }

        return null;
    }

    public static ParametersBase loadASN1Params(String path) {
        String pathToFile = path + "/params.txt";
        String base64String = FileWriteReadHelper.fileToString(pathToFile);
        if (base64String == null) {
            System.out.println("Niepoprawna ścieżka lub uszkodzone pliki - kończenie pracy aplikacji");
            System.exit(64);
        }
        ASN1Sequence seq = null;
        try {
            seq = (ASN1Sequence) BEROctetString.fromByteArray(Base64.decode(base64String.getBytes()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return new ParametersBase(
                ((ASN1Integer) seq.getObjectAt(0)).getValue().intValue(),
                ((ASN1Integer) seq.getObjectAt(1)).getValue().intValue(),
                ((ASN1Integer) seq.getObjectAt(2)).getValue().intValue(),
                ((ASN1Integer) seq.getObjectAt(3)).getValue().intValue(),
                ((ASN1Integer) seq.getObjectAt(4)).getValue().intValue(),
                ((ASN1Integer) seq.getObjectAt(5)).getValue().intValue(),
                ((ASN1Integer) seq.getObjectAt(6)).getValue().intValue(),
                ((BEROctetString) seq.getObjectAt(7)).getOctets());
    }

    public static String fileToString(String filePath) {
        String content = "";

        try {
            content = new String(Files.readAllBytes(Paths.get(filePath)));
        } catch (IOException e) {
            System.out.println("Nie ma takiego pliku");
            content = null;
        }

        return content;
    }

    public static void stringToFile(String filePath, String msg)
            throws IOException {
        FileOutputStream outputStream = new FileOutputStream(filePath);
        byte[] strToBytes = msg.getBytes();
        outputStream.write(strToBytes);

        outputStream.close();
    }

}
