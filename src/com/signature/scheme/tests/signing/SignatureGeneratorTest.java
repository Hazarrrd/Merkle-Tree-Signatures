package com.signature.scheme.tests.signing;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.keys.KeysKeeper;
import com.signature.scheme.keys.PrivateKey;
import com.signature.scheme.keys.PublicKey;
import com.signature.scheme.signing.Signature;
import com.signature.scheme.signing.SignatureGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureGeneratorTest {

    @Test
    void signMessage() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m,params.n,params.kU,params.kL,params.upperH,params.lowerH,params.wL,params.wU,params.treeGrowth);
        keysKeeper.generateKeys();

        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        int size = (int) Math.pow(2,params.lowerH);
        for(int j = 0;j<size;j++) {
            System.out.println(j);
            Signature signature = signatureGenerator.signMessage("TESTOWA WIDOMOSC");

            assertEquals(signature.treeIndex, 0);
            assertEquals(signature.lowerTreeSignature[0].length, params.n);
            assertEquals(signature.upperAuthPath.length, params.upperH );
            for (int i = 0; i < signature.upperAuthPath.length; i++) {
                assertEquals(signature.upperAuthPath[i].height, i);
                assertEquals(signature.upperAuthPath[i].value.length, params.n);
                assertEquals(signature.upperAuthPath[i].index, 1);
            }

            assertEquals(signature.index, j);
            assertEquals(signature.msgSignature[0].length, params.n);
            assertEquals(signature.lowerAuthPath.length, params.lowerH);
            for (int i = 0; i < signature.lowerAuthPath.length; i++) {
                assertEquals(signature.lowerAuthPath[i].height, i);
                assertEquals(signature.lowerAuthPath[i].value.length, params.n);
            }
        }

        for(int j = 0;j<size;j++) {
            Signature signature = signatureGenerator.signMessage("TESTOWA WIDOMOSC");

            assertEquals(signature.treeIndex, 1);
            assertEquals(signature.lowerTreeSignature[0].length, params.n);
            assertEquals(signature.upperAuthPath.length, params.upperH );
            assertEquals(signature.upperAuthPath[0].index, 0);
            for (int i = 1; i < signature.upperAuthPath.length; i++) {
                assertEquals(signature.upperAuthPath[i].height, i);
                assertEquals(signature.upperAuthPath[i].value.length, params.n);
                assertEquals(signature.upperAuthPath[i].index, 1);
            }

            assertEquals(signature.index, j);
            assertEquals(signature.msgSignature[0].length, params.n);
            for (int i = 0; i < signature.lowerAuthPath.length; i++) {
                assertEquals(signature.lowerAuthPath[i].height, i);
                assertEquals(signature.lowerAuthPath[i].value.length, params.n);
            }
        }
    }

    @Test
    void signLowerTree() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m,params.n,params.kU,params.kL,params.upperH,params.lowerH,params.wL,params.wU,params.treeGrowth);
        keysKeeper.privateKey = new PrivateKey();
        keysKeeper.publicKey = new PublicKey();
        keysKeeper.publicKey.bitmaskMain = keysKeeper.params.bitmaskMain;
        keysKeeper.publicKey.bitmaskLTree = keysKeeper.params.bitmaskLTree;
        keysKeeper.publicKey.X = params.X;
        byte[] root = keysKeeper.generateTrees();
        SignatureGenerator.signLowerTree(keysKeeper.privateKey,params.n,params.ll1,params.ll2,params.wL,params.X,root);
        Signature signature = keysKeeper.privateKey.lowerSignature;
        assertEquals(signature.treeIndex,0);
        assertEquals(signature.lowerTreeSignature[0].length,params.n);
        assertEquals(signature.upperAuthPath.length,params.upperH);
        for (int i =0;i<signature.upperAuthPath.length;i++){
            assertEquals(signature.upperAuthPath[i].height , i);
            assertEquals(signature.upperAuthPath[i].value.length , params.n);
            assertEquals(signature.upperAuthPath[i].index , 1);
        }
    }
}