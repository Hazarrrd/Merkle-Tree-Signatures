package com.signature.scheme.tests.keys;

import com.signature.scheme.ParametersBase;
import com.signature.scheme.keys.WOTSkeyGenerator;
import com.signature.scheme.tools.HelperFunctions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WOTSkeyGeneratorTest {

    @Test
    void computeOTSPublicKey() {
        ParametersBase params = new ParametersBase();
        byte[][] signature = new byte[params.lL][params.n];
        for (int i = 0; i < params.lL; i++) {
            byte[] array = new byte[params.n];
            HelperFunctions.fillBytesRandomly(array);
            signature[i] = array;
        }
        byte[][] pk = WOTSkeyGenerator.computeWOTSPublicKey(params.seed, params.ll1, params.ll2, params.wL, params.X, signature);
        assertEquals(pk.length, params.lL);
        for (byte[] array : pk) {
            assertEquals(array.length, params.n);
        }
    }
}