package com.signature.scheme.algorithm.applications;

import com.signature.scheme.algorithm.keys.ParametersBase;
import com.signature.scheme.algorithm.keys.PublicKey;
import com.signature.scheme.algorithm.merkleTree.Node;
import com.signature.scheme.algorithm.signing.Signature;
import com.signature.scheme.algorithm.signing.StructureSignature;
import com.signature.scheme.algorithm.tools.FileWriteReadHelper;
import com.signature.scheme.algorithm.verfication.SignatureVerficator;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Scanner;

import static com.signature.scheme.algorithm.tools.HelperFunctions.ceilLogTwo;

/**
 * Application that verify digital signatures
 */
public class VerifyApplication {
    private SignatureVerficator signatureVerficator;

    public VerifyApplication(String path) {
        ParametersBase params = FileWriteReadHelper.loadParams(path);
        signatureVerficator = new SignatureVerficator(loadASN1PublicKey(path, params)
                , params);
    }

    public static void main(String[] args) {
        startVerifyApp();
    }

    public static void startVerifyApp() {
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
        Signature signature = this.loadASN1Signature(pathToSignature);
        // String msg = FileWriteReadHelper.loadMsg(pathToSignature, "/msg.txt");
        if (signature != null) {
            String msg = FileWriteReadHelper.fileToString(pathToSignature + "/msg.txt");
            Boolean valid = signatureVerficator.verifySignature(signature, msg);
            if (valid == true) {
                System.out.println("PODPIS JEST PRAWIDŁOWY");
            } else {
                System.out.println("ERROR - PODPIS NIE JEST PRAWIDŁOWY");
            }
        }

    }

    public static PublicKey loadASN1PublicKey(String path, ParametersBase params) {

        String base64String = FileWriteReadHelper.fileToString(path + "/publicKey.txt");
        ASN1Sequence seq = null;
        try {
            seq = (ASN1Sequence) BEROctetString.fromByteArray(Base64.decode(base64String.getBytes()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        PublicKey newKey = new PublicKey();

        int sizeL = ceilLogTwo(params.maxL);
        int sizeSingleByteArray = 2 * params.n;

        newKey.bitmaskLTree = getBytesDoubleArray(seq, sizeL, sizeSingleByteArray, 0);

        int sizeMain = params.maxH;
        newKey.bitmaskMain = getBytesDoubleArray(seq, sizeMain, sizeSingleByteArray, sizeL);

        newKey.X = ((BEROctetString) seq.getObjectAt(sizeL + sizeMain)).getOctets();
        newKey.upperRoot = ((BEROctetString) seq.getObjectAt(sizeL + sizeMain + 1)).getOctets();

        return newKey;
    }

    public static PublicKey loadSerializedPublicKey(String path) {
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


    public Signature loadASN1Signature(String path) {
        ParametersBase params = this.signatureVerficator.params;
        String base64String = FileWriteReadHelper.fileToString(path + "/signature.txt");
        if (base64String == null) {
            System.out.println("Podpis o tym indeksie nie został złożony");
            return null;
        }
        ASN1Sequence seq = null;
        try {
            seq = (ASN1Sequence) BEROctetString.fromByteArray(Base64.decode(base64String.getBytes()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Signature newSignature = new Signature();
        int startIndex = 0;

        newSignature.index = ((ASN1Integer) seq.getObjectAt(startIndex)).getValue().intValue();
        startIndex++;
        newSignature.treeIndex = ((ASN1Integer) seq.getObjectAt(startIndex)).getValue().intValue();
        startIndex++;

        int lowerH = params.lowerH;
        if (params.treeGrowth == 1) {
            lowerH += newSignature.treeIndex;
        }

        newSignature.upperAuthPath = getNodesArray(params, params.upperH, seq, startIndex);
        startIndex += params.upperH;
        newSignature.lowerTreeSignature = getBytesDoubleArray(seq, params.lU, params.n, startIndex);

        startIndex += params.lU;
        newSignature.lowerAuthPath = getNodesArray(params, lowerH, seq, startIndex);
        startIndex += lowerH;
        newSignature.msgSignature = getBytesDoubleArray(seq, params.lL, params.n, startIndex);
        startIndex += params.lL;


        ArrayList<StructureSignature> newStructureSignatures = new ArrayList<>();
        for (int z = startIndex; z < seq.size(); z++) {
            BERSequence asn1StructureSignatures = (BERSequence) (seq.getObjectAt(z));
            newStructureSignatures.add(new StructureSignature(getNodesArray(params, params.upperH, asn1StructureSignatures, 0)
                    , getBytesDoubleArray(asn1StructureSignatures, params.lL, params.n, lowerH)));
        }

        newSignature.structureSignatures = newStructureSignatures;

        return newSignature;
    }


    public Signature loadSerializedSignature(String path) {
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

    private static byte[][] getBytesDoubleArray(ASN1Sequence seq, int sizeL, int sizeSingleByteArray, int startIndex) {
        byte[][] newbitmask = new byte[sizeL][sizeSingleByteArray];
        for (int z = 0; z < sizeL; z++) {
            newbitmask[z] = ((BEROctetString) seq.getObjectAt(z + startIndex)).getOctets();
        }
        return newbitmask;
    }

    private static Node[] getNodesArray(ParametersBase params, int size, ASN1Sequence seq, int startIndex) {
        Node[] newAuthPath = new Node[size];
        for (int z = 0; z < size; z++) {
            BERSequence asn1Node = (BERSequence) (seq.getObjectAt(z + startIndex));
            newAuthPath[z] = new Node(((ASN1Integer) (asn1Node.getObjectAt(0))).getValue().intValue()
                    , ((BEROctetString) (asn1Node.getObjectAt(1))).getOctets(), ((ASN1Integer) (asn1Node.getObjectAt(2))).getValue().intValue());
        }
        return newAuthPath;
    }
}
