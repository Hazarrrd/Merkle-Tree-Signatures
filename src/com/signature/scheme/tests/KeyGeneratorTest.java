package com.signature.scheme.tests;

import com.signature.scheme.KeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyGeneratorTest {

    @Test
    void generateKeys() {
        KeyGenerator keyGenerator = new KeyGenerator(100,32,4,4,12,12,8,8);
        keyGenerator.generateKeys();
    }
}