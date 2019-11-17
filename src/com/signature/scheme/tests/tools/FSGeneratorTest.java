package com.signature.scheme.tests.tools;

import com.signature.scheme.tools.FSGenerator;
import com.signature.scheme.tools.HelperFunctions;
import com.signature.scheme.tools.PseudorndFunction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FSGeneratorTest {
    FSGenerator f;
    byte[] array;
    int n;

    @BeforeEach
    void setUp() {
        n = 32;
        array = new byte[n];
        HelperFunctions.fillBytesRandomly(array);
        f = new FSGenerator(new PseudorndFunction(n), new PseudorndFunction(n), array);
    }

    @Test
    void nextStateAndSeed() {
        byte[] previousState = f.state;
        byte[] seed = f.nextStateAndSeed();
        byte[] afterState = f.state;
        assertNotEquals(previousState, afterState);
        assertNotEquals(seed, afterState);
        assertNotNull(seed);

        byte[] previousState2 = f.state;
        byte[] seed2 = f.nextStateAndSeed();
        byte[] afterState2 = f.state;
        assertNotEquals(previousState, afterState);
        assertNotEquals(seed2, afterState2);
        assertNotNull(seed2);

        assertNotEquals(afterState2, afterState);
        assertNotEquals(seed, seed2);
    }

    @Test
    void nextState() {
        assertNotNull(f.state);
        byte[] previousState = f.state;
        byte[] afterStateFromReturn = f.nextState();
        byte[] afterState = f.state;
        assertEquals(afterState, afterStateFromReturn);
        assertNotEquals(previousState, afterState);

        byte[] seed2 = f.nextState();
        byte[] afterState2 = f.state;
        assertEquals(seed2, afterState2);
        assertNotNull(seed2);
        assertNotEquals(afterState2, afterState);
    }

    @Test
    void getSeedValue() {
        assertNotNull(f.state);
        byte[] seed = f.getSeedValue();
        assertNotNull(seed);
    }
}