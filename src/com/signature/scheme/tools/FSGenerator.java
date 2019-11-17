package com.signature.scheme.tools;

public class FSGenerator {
    private PseudorndFunction otsSeedGenerator;
    private PseudorndFunction nextStateGenerator;
    public final byte[] initialState;
    public byte[] state;
    private byte[] starter0;
    private byte[] starter1;

    public FSGenerator(PseudorndFunction otsSeedGenerator, PseudorndFunction nextStateGenerator, byte[] state) {
        this.otsSeedGenerator = otsSeedGenerator;
        this.nextStateGenerator = nextStateGenerator;
        this.state = state;
        this.initialState = state;
        int n = state.length;
        starter0 = new byte[n];
        starter1 = new byte[n];
        for (int i = 0; i < n; i++) {
            starter0[i] = 0;
            starter1[i] = 0;
        }
        starter1[n - 1] = 1;

    }

    public byte[] nextStateAndSeed() {

        //BITY DO POPRAWY
        otsSeedGenerator.setKey(state);
        nextStateGenerator.setKey(state);
        this.state = nextStateGenerator.encrypt(starter0);
        return otsSeedGenerator.encrypt(starter1);
    }

    public byte[] nextState() {
        nextStateGenerator.setKey(state);
        this.state = nextStateGenerator.encrypt(starter0);
        return this.state;
    }

    public byte[] getSeedValue() {
        otsSeedGenerator.setKey(state);
        return otsSeedGenerator.encrypt(starter1);
    }

}
