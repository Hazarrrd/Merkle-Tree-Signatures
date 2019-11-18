package com.signature.scheme.tests.signing;

import com.signature.scheme.KeysKeeper;
import com.signature.scheme.ParametersBase;
import com.signature.scheme.PrivateKey;
import com.signature.scheme.Signature;
import com.signature.scheme.signing.SignatureGenerator;
import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HelperFunctions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignatureGeneratorTest {

    @Test
    void signMessage() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m,params.n,params.kU,params.kL,params.upperH,params.lowerH,params.wL,params.wU);
        keysKeeper.generateKeys();

        SignatureGenerator signatureGenerator = new SignatureGenerator(keysKeeper);
        int size = (int) Math.pow(2,params.lowerH);
        for(int j = 0;j<size;j++) {
            Signature signature = signatureGenerator.signMessage("TESTOWA WIDOMOSC");

            assertEquals(signature.treeIndex, 0);
            assertEquals(signature.lowerTreeSignature.length, params.n);
            assertEquals(signature.upperAuthPath.length, params.upperH - 1);
            for (int i = 0; i < signature.upperAuthPath.length; i++) {
                assertEquals(signature.upperAuthPath[i].height, i);
                assertEquals(signature.upperAuthPath[i].value.length, params.n);
                assertEquals(signature.upperAuthPath[i].index, 1);
            }

            assertEquals(signature.index, j);
            assertEquals(signature.msgSignature.length, params.n);
            assertEquals(signature.lowerAuthPath.length, params.upperH - 1);
            for (int i = 0; i < signature.lowerAuthPath.length; i++) {
                assertEquals(signature.lowerAuthPath[i].height, i);
                assertEquals(signature.lowerAuthPath[i].value.length, params.n);
            }
        }
    }

    @Test
    void signLowerTree() {
        ParametersBase params = new ParametersBase();
        KeysKeeper keysKeeper = new KeysKeeper(params.m,params.n,params.kU,params.kL,params.upperH,params.lowerH,params.wL,params.wU);
        byte[] root = keysKeeper.generateTrees();

        Signature signature = SignatureGenerator.signLowerTree(keysKeeper.privateKey,params.n,params.ll1,params.ll2,params.wL,params.X,root);
        assertEquals(signature.treeIndex,0);
        assertEquals(signature.lowerTreeSignature.length,params.n);
        assertEquals(signature.lowerAuthPath.length,params.upperH-1);
        for (int i =0;i<signature.lowerAuthPath.length;i++){
            assertEquals(signature.lowerAuthPath[i].height , i);
            assertEquals(signature.lowerAuthPath[i].value.length , params.n);
            assertEquals(signature.lowerAuthPath[i].index , 1);
        }
    }
}