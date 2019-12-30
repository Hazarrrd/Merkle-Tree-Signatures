package com.signature.scheme.algorithm.tools;

import com.signature.scheme.algorithm.keys.ParametersBase;

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

    public static void sendParams(ParametersBase params, String path) {
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

    public static ParametersBase loadParams(String path) {

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
