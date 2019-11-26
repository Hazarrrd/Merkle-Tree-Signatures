package com.signature.scheme;

import com.signature.scheme.keys.KeysKeeper;
import com.signature.scheme.signing.Signature;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.verfication.SignatureVerficator;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

public class PerformanceTests {

    static FileOutputStream outputStream;
    static double memoryBefore;
    static double startTime;
    static double memoryAfter;
    static double stopTime;
    static double memoryResult;
    static double timeResult;
    static String folder;

    public static void main(String[] args) {
        doTestTreeGrowth0();
        doTestTreeGrowth1();

    }

    public static void doTestTreeGrowth0() {
        folder = "treeGrowth_0";
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);
        ParametersBase params = new ParametersBase(m, n, 2, 2, 4, 4, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println("ROZGRZEWKA - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 2, 2, 4, 4, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println("Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 6, 6, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 8, 8, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 10, 10, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 16, 16, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 18, 18, 16, 16, x, 0);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);
    }

    public static void doTestTreeGrowth1() {
        folder = "treeGrowth_1";
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);
        ParametersBase params = new ParametersBase(m, n, 2, 2, 4, 2, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println("ROZGRZEWKA - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 2, 2, 4, 2, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println("Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 6, 6, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 3, 6, 7, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 8, 6, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 2, 10, 4, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 10, 6, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 10, 10, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

        params = new ParametersBase(m, n, 4, 4, 18, 18, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);
    }

    public static void testThatConfiguration(ParametersBase params) {
        byte[] m = new byte[100];
        HelperFunctions.fillBytesRandomly(m);
        KeysKeeper keysKeeper = new KeysKeeper(params);
        int signaturesToMake = 10000;

        String path = "/home/janek/IdeaProjects/MerkleSignatures/" + folder + "/" + "Test" + "__" + params.treeGrowth + "__"
                + params.upperH + "__" + params.lowerH + "_w_" + params.wU + "_k_" + params.kU;
        File targetFile = new File(path + "/testsResult.txt");
        File parent = targetFile.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Couldn't create dir: " + parent);
        }

        try {
            outputStream = new FileOutputStream(path + "/testsResults.txt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        String initialString = "For params : " + " ; n -> " + params.n + " ; m -> " + params.m + " ; upperH -> " + params.upperH
                + " ; lowerH -> " + params.lowerH + " ; n -> " + params.treeGrowth
                + " ; kU -> " + params.kU + " ; kL -> " + params.kL
                + " ; wU -> " + params.wU + " ; wL -> " + params.wL;
        writeToFile(initialString);

        Runtime runtime = Runtime.getRuntime();

        //TESTING KEYS GENERATION

        startTime();
        beforeMemory(runtime);
        keysKeeper.generateKeys();
        memoryAfter(runtime);
        stopTime();
        timeResult();


        memoryResult();
        writeToFile("Memory keys : " + memoryResult);

        writeToFile("Generation time : " + timeResult);
        System.out.println("Time : " + timeResult + " Memory : " + memoryResult);

        //TESTING SIGNATURE GENERATION
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey, keysKeeper.params);
        String msg = "TestingMsg";
        ArrayList<Double> timesGeneration = new ArrayList<>();
        ArrayList<Double> memorySignature = new ArrayList<>();
        Signature[] signatures = new Signature[signaturesToMake];

        for (int i = 0; i < signaturesToMake; i++) {

            startTime();
            beforeMemory(runtime);
            signatures[i] = signatureGenerator.signMessage(msg + i);
            memoryAfter(runtime);
            stopTime();
            timesGeneration.add(timeResult());
            memorySignature.add(memoryResult());
        }


        //TESTING SIGNATURE VERIFICATION
        ArrayList<Double> timesVerification = new ArrayList<>();

        for (int i = 0; i < signaturesToMake; i++) {
            startTime();
            Boolean isValid = signatureVerficator.verifySignature(signatures[i], msg + i);
            stopTime();
            timesVerification.add(timeResult());

            if (isValid) {
                // System.out.println("SIGNATURE IS FINE");
            } else {
                System.out.println("SIGNATURE IS FALSED, ERROR");
            }
        }

        writeToFile("");
        writeToFile("Generate signature time MAX: " + Collections.max(timesGeneration));
        writeToFile("Signature memory MAX: " + Collections.max(memorySignature));
        writeToFile("Verification time MAX : " + Collections.max(timesVerification));
        writeToFile("");
        writeToFile("Generate signature time MIN: " + Collections.min(timesGeneration));
        writeToFile("Signature memory MIN: " + Collections.min(memorySignature));
        writeToFile("Verification time MIN : " + Collections.min(timesVerification));
        writeToFile("");
        Double average = timesGeneration.stream().mapToDouble(val -> val).average().orElse(0.0);
        writeToFile("Generate signature AVG : " + average);
        average = memorySignature.stream().mapToDouble(val -> val).average().orElse(0.0);
        writeToFile("Signature memory AVG : " + average);
        average = timesVerification.stream().mapToDouble(val -> val).average().orElse(0.0);
        writeToFile("Verification time AVG : " + average);
        writeToFile("");


        for (int i = 0; i < signaturesToMake; i = i + 1) {
            writeToFile("INDEX : " + signatures[i].index + " TREEINDEX : " + signatures[i].treeIndex + " STRUCT INDEX : " + signatures[i].structureSignatures.size());
            writeToFile("Generate signature time: " + timesGeneration.get(i));
            writeToFile("Signature memory : " + memorySignature.get(i));
            writeToFile("Verification time : " + timesVerification.get(i));
            writeToFile("");
        }

        Chart verificationChart = new Chart(timesVerification, path, "Czas weryfikacji");
        Chart SigningChart = new Chart(timesGeneration, path, "Czas podpisywania");
        Chart SigntureMemoryChart = new Chart(memorySignature, path, "Pamięć sygnatur");


        try {
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static double memoryResult() {
        memoryResult = memoryAfter - memoryBefore;
        return memoryResult;
    }

    public static double timeResult() {
        timeResult = stopTime - startTime;
        return timeResult;
    }

    public static void memoryAfter(Runtime runtime) {
        memoryAfter = runtime.totalMemory() - runtime.freeMemory();
    }

    public static void stopTime() {
        stopTime = System.currentTimeMillis();
    }

    public static void startTime() {
        startTime = System.currentTimeMillis();
    }

    public static void beforeMemory(Runtime runtime) {
        memoryBefore = runtime.totalMemory() - runtime.freeMemory();
    }

    public static void writeToFile(String string) {
        try {
            string += "\n";
            byte[] data = string.getBytes();
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


}
