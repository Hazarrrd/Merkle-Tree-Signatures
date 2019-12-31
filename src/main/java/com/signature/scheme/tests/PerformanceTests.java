package com.signature.scheme.tests;

import com.signature.scheme.algorithm.keys.KeysKeeper;
import com.signature.scheme.algorithm.keys.ParametersBase;
import com.signature.scheme.algorithm.signing.Signature;
import com.signature.scheme.algorithm.signing.SignatureGenerator;
import com.signature.scheme.algorithm.tools.HelperFunctions;
import com.signature.scheme.algorithm.verfication.SignatureVerficator;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Class doing performance tests
 */
public class PerformanceTests {

    static FileOutputStream outputStream;
    static double memoryBefore;
    static double startTime;
    static double memoryAfter;
    static double stopTime;
    static double memoryResult;
    static double timeResult;
    static String folder;
    static int signaturesToMake;

    public static void main(String[] args) {
        //doTestTreeGrowth0();
        //doTestTreeGrowth1();
        //  doTestTreeGrowth2();
        compare();
    }

    public static void compare() {
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);

        signaturesToMake = 10000000;
        folder = "testTwoTrees";


        ParametersBase params = new ParametersBase(m, n, 2, 3, 6, 7, 16, 16, x, 1);
        testThatConfiguration(params);

        // ParametersBase params2 = new ParametersBase(m, n, 2, 3, 4, 5, 16, 16, x, 1);
        // testThatConfiguration(params2);


    }

    public static void doSmallTreeTest() {
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);

        signaturesToMake = 10000;

        System.out.println("\\begin{center}");
        System.out.println("\\begin{tabular}{| c | c | c | c |}");
        System.out.println("\\hline");
        System.out.println("\\multicolumn{4}{|c|}{Czasy " + signaturesToMake + " podpisów dla struktury : H górne = 3, H dolne = 2} \\\\");
        System.out.println("\\hline");
        System.out.println("struktura & śr. czas podpisu & podpis [ostatni liść] & śr. czas weryfikacji \\\\");
        System.out.println("\\hline");
        System.out.println("\\hline");

        ParametersBase params = new ParametersBase(m, n, 3, 2, 3, 2, 16, 16, x, 1);
        testThatConfiguration(params);

        System.out.println("\\end{tabular}");
        System.out.println("\\end{center}");
    }

    public static void doGenerationTest() {
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);

        System.out.println("\\begin{center}");
        System.out.println("\\begin{tabular}{| c | c | c | c | c | c |}");
        System.out.println("\\hline");
        System.out.println("\\multicolumn{3}{|c|}{XMMS+} & \\multicolumn{3}{c|}{schemat z rosnącymi wysokościami} \\\\");
        System.out.println("\\hline");
        System.out.println("H górne & H dolne & czas generowania kluczy & H górne & H dolne & czas generowania kluczy \\\\");
        System.out.println("\\hline");
        System.out.println("\\hline");

        ParametersBase params = new ParametersBase(m, n, 2, 2, 7, 7, 16, 16, x, 0);
        ParametersBase params2 = new ParametersBase(m, n, 2, 2, 3, 7, 16, 16, x, 1);

        keyGenTimeTestHelper(params, params2);

        params = new ParametersBase(m, n, 2, 2, 10, 10, 16, 16, x, 0);
        params2 = new ParametersBase(m, n, 2, 2, 4, 5, 16, 16, x, 1);

        keyGenTimeTestHelper(params, params2);

        params = new ParametersBase(m, n, 2, 2, 15, 15, 16, 16, x, 0);
        params2 = new ParametersBase(m, n, 2, 2, 4, 15, 16, 16, x, 1);

        keyGenTimeTestHelper(params, params2);

        params = new ParametersBase(m, n, 2, 2, 20, 20, 16, 16, x, 0);
        params2 = new ParametersBase(m, n, 2, 2, 5, 9, 16, 16, x, 1);

        keyGenTimeTestHelper(params, params2);

        System.out.println("\\end{tabular}");
        System.out.println("\\end{center}");
    }

    public static void keyGenTimeTestHelper(ParametersBase params, ParametersBase params2) {
        KeysKeeper keysKeeper = new KeysKeeper(params);
        startTime();
        keysKeeper.generateKeys();
        stopTime();
        long time = (long) timeResult();

        KeysKeeper keysKeeper2 = new KeysKeeper(params2);
        startTime();
        keysKeeper2.generateKeys();
        stopTime();
        long time2 = (long) timeResult();

        System.out.println(params.upperH + " & " + params.lowerH + " & " + time + " & " + params2.upperH + " & " + params2.lowerH + " & " + time2 + " \\\\ ");
        System.out.println("\\hline");
    }

    public static void signatureNumberCalculator0() {
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);
        for (int i = 2; i < 25; i++) {
            ParametersBase params = new ParametersBase(m, n, 2, 2, i, i, 16, 16, x, 0);
            ParametersBase params2 = new ParametersBase(m, n, 2, 2, i, i, 16, 16, x, 1);
            String number0 = "$(2^{" + params.upperH + "}-1)*2^{" + params.lowerH + "}$";
            String number1 = "$2^{" + (params2.lowerH + params2.upperSize - 1) + "}-2^{" + params2.lowerH + "}$";
            System.out.println(params.upperH + " & " + params.lowerH + " & " + params.signaturesNumber + " & "
                    + params2.upperH + " & " + params2.lowerH + " & " + params2.signaturesNumber + " \\\\ ");
            System.out.println("\\hline");

        }
    }

    public static void signatureNumberCalculator1() {
        int n = 16;
        int m = 32;
        byte[] x = new byte[n];
        int startup = 17;
        int endup = 21;
        int start = 2;
        int end = 20;
        System.out.println("\\begin{center}");
        String columns = "| l ||";
        String columnOne = "";
        for (int i = startup; i < endup + 1; i++) {
            columns += " c |";
            columnOne += " & górneH = " + i;
        }
        System.out.println("\\begin{tabular}{" + columns + "}");
        System.out.println("\\hline");
        System.out.println("\\multicolumn{" + (endup - startup + 2) + "}{|c|}{LICZBA MOŻLIWYCH PODPISÓW DLA RÓŻNYCH WYSOKOŚCI} \\\\");
        System.out.println("\\hline");
        System.out.println("\\hline");
        System.out.println("\\hline");
        System.out.println(columnOne + " \\\\");
        System.out.println("\\hline");
        System.out.println("\\hline");

        HelperFunctions.fillBytesRandomly(x);
        for (int j = start; j < end + 1; j++) {
            ParametersBase params2 = new ParametersBase(m, n, 2, 2, startup, j, 16, 16, x, 1);
            String string = "dolneH =  " + j + " & $2^{" + (params2.lowerH + params2.upperSize - 1) + "}-2^{" + params2.lowerH + "}$";
            for (int i = startup + 1; i < endup + 1; i++) {
                params2 = new ParametersBase(m, n, 2, 2, i, j, 16, 16, x, 1);
                String number1 = "$2^{" + (params2.lowerH + params2.upperSize - 1) + "}-2^{" + params2.lowerH + "}$";
                string += " & " + number1;
            }
            System.out.println(string + " \\\\ ");
            System.out.println("\\hline");
        }
        System.out.println("\\end{tabular}");
        System.out.println("\\end{center}");
    }

    public static void doTestTreeGrowth0() {
        folder = "treeGrowth_0";
        int n = 16;
        int m = 32;
        signaturesToMake = 10000;
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
        signaturesToMake = 10000;
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

    public static void doTestTreeGrowth2() {
        folder = "treeGrowth_1_NIGHTTEST2";
        int n = 16;
        int m = 32;
        signaturesToMake = 10000;
        byte[] x = new byte[n];
        HelperFunctions.fillBytesRandomly(x);
        ParametersBase params = new ParametersBase(m, n, 2, 2, 4, 2, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println("ROZGRZEWKA - > " + params.signaturesNumber);
        signaturesToMake = Integer.MAX_VALUE;
        params = new ParametersBase(m, n, 4, 3, 6, 7, 16, 16, x, 1);
        testThatConfiguration(params);
        System.out.println(params.upperH + " Ile mieści struktura - > " + params.signaturesNumber);

    }

    public static void testThatConfiguration(ParametersBase params) {
        byte[] m = new byte[100];
        HelperFunctions.fillBytesRandomly(m);
        KeysKeeper keysKeeper = new KeysKeeper(params);

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
                + " ; lowerH -> " + params.lowerH + " ; treeGrowth -> " + params.treeGrowth
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
        writeToFile("Possible signtures per structure : " + params.signaturesNumber);
        System.out.println("Time : " + timeResult + " Memory : " + memoryResult);

        //TESTING SIGNATURE GENERATION
        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        SignatureVerficator signatureVerficator = new SignatureVerficator(keysKeeper.publicKey, keysKeeper.params);
        String msg = "TestingMsg";
        ArrayList<Double> timesGeneration = new ArrayList<>();
        //  ArrayList<Double> memorySignature = new ArrayList<>();
        ArrayList<Double> timesVerification = new ArrayList<>();
        ArrayList<Signature> signatures = new ArrayList<>();
        Double average;
        double sigTimeAvg = 0;
        double validateTimeAvg = 0;
        int actualH = 0;
        int actualStruct = 0;
        long maxGener = 0;
        long minGener = Long.MAX_VALUE;
        long maxVer = 0;
        long minVer = Long.MAX_VALUE;
        long previousSize = params.lowerSize;

        for (int i = 0; i < signaturesToMake; i++) {

            startTime();
            //  beforeMemory(runtime);
            signatures.add(signatureGenerator.signMessage(msg + i));
            //   memoryAfter(runtime);
            stopTime();
            timesGeneration.add(timeResult());
            if (timeResult < minGener) {
                minGener = (long) timeResult;
            }

            if (timeResult > maxGener) {
                maxGener = (long) timeResult;
            }
            String string = "";
            if (actualH == signatures.get(i).treeIndex) {
                sigTimeAvg += timeResult;
            } else {
                writeToFile("Generate signature time AVG : " + round(sigTimeAvg / previousSize, 3) +
                        " Generate time MAX : " + maxGener + " Generate time MIN : " + minGener + " for treeIndex " + actualH);
                string += +(actualH) + " & " + round(sigTimeAvg / previousSize, 3) + " & "
                        + maxGener + " & " + minGener + " & " + timesGeneration.get(i - 1) + " & ";
                sigTimeAvg = (long) timeResult;
            }
            //  memorySignature.add(memoryResult());

            //TESTING SIGNATURE VERIFICATION

            startTime();
            Boolean isValid = signatureVerficator.verifySignature(signatures.get(i), msg + i);
            stopTime();
            timesVerification.add(timeResult());
            if (timeResult < minVer) {
                minVer = (long) timeResult;
            }

            if (timeResult > maxVer) {
                maxVer = (long) timeResult;
            }
            if (actualH == signatures.get(i).treeIndex) {
                validateTimeAvg += timeResult;
            } else {
                writeToFile("Validation time AVG : " + round(validateTimeAvg / previousSize, 3) +
                        " Validation time MAX : " + maxVer + " Validation time MIN : " + minVer + " for treeIndex " + actualH);
                writeToFile("");
                string += round(validateTimeAvg / previousSize, 3) + " & "
                        + maxVer + " & " + minVer + " \\\\";
                previousSize = params.lowerSize;
                validateTimeAvg = (long) timeResult;
                actualH++;
                System.out.println(string);
                System.out.println("\\hline");
                maxGener = 0;
                minGener = Long.MAX_VALUE;
                maxVer = 0;
                minVer = Long.MAX_VALUE;
            }

            if (isValid) {
                //System.out.println("SIGNATURE IS FINE");
            } else {
                System.out.println("SIGNATURE IS FALSED, ERROR");
                return;
            }
            actualStruct = signatures.get(i).structureSignatures.size();
            writeToFile("INDEX : " + i + " LOWER LEAF INDEX : " + signatures.get(i).index + " TREEINDEX : " + signatures.get(i).treeIndex + " LOWER TREESIZE : " + params.lowerSize + " STRUCT INDEX : " + signatures.get(i).structureSignatures.size());
            writeToFile("Generate signature time: " + timesGeneration.get(i));
            //writeToFile("Signature memory : " + memorySignature.get(i));
            writeToFile("Verification time : " + timesVerification.get(i));
            writeToFile("");

        }

       /* String string ="" + (actualStruct+1) + " & "  + round(sigTimeAvg/previousSize,3) + " & " + timesGeneration.get(timesGeneration.size()-1) + " & ";
        string += round(validateTimeAvg/previousSize,3) + " \\\\";
        System.out.println(string);
        System.out.println("\\hline");*/

        writeToFile("");
        writeToFile("Generate signature time MAX: " + Collections.max(timesGeneration));
        //    writeToFile("Signature memory MAX: " + Collections.max(memorySignature));
        writeToFile("Verification time MAX : " + Collections.max(timesVerification));
        writeToFile("");
        writeToFile("Generate signature time MIN: " + Collections.min(timesGeneration));
        //writeToFile("Signature memory MIN: " + Collections.min(memorySignature));
        writeToFile("Verification time MIN : " + Collections.min(timesVerification));
        writeToFile("");
        average = timesGeneration.stream().mapToDouble(val -> val).average().orElse(0.0);
        writeToFile("Generate signature AVG : " + average);
        // average = memorySignature.stream().mapToDouble(val -> val).average().orElse(0.0);
        //   writeToFile("Signature memory AVG : " + average);
        average = timesVerification.stream().mapToDouble(val -> val).average().orElse(0.0);
        writeToFile("Verification time AVG : " + average);
        writeToFile("");

/*
        for (int i = 0; i < signaturesToMake; i = i + 1) {
            writeToFile("INDEX : " + signatures[i].index + " TREEINDEX : " + signatures[i].treeIndex + " STRUCT INDEX : " + signatures[i].structureSignatures.size());
            writeToFile("Generate signature time: " + timesGeneration.get(i));
            writeToFile("Signature memory : " + memorySignature.get(i));
            writeToFile("Verification time : " + timesVerification.get(i));
            writeToFile("");
        }*/

        Chart verificationChart = new Chart(timesVerification, path, "Czas weryfikacji");
        Chart SigningChart = new Chart(timesGeneration, path, "Czas podpisywania");
        //  Chart SigntureMemoryChart = new Chart(memorySignature, path, "Pamięć sygnatur");


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

    public static double round(double value, int places) {
        double scale = Math.pow(10, places);
        return Math.round(value * scale) / scale;
    }


}
