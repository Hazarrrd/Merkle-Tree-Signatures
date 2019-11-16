package com.signature.scheme.tools;

public class FSGenerator {
    private PseudorndFunction otsSeedGenerator;
    private PseudorndFunction nextStateGenerator;
    public final byte[] initialState;
    public byte[] state;

    public FSGenerator(PseudorndFunction otsSeedGenerator, PseudorndFunction nextStateGenerator, byte[] state) {
        this.otsSeedGenerator = otsSeedGenerator;
        this.nextStateGenerator = nextStateGenerator;
        this.state = state;
        this.initialState = state;
    }

    public byte[] next(){

        //BITY DO POPRAWY
        otsSeedGenerator.setKey(state);
        nextStateGenerator.setKey(state);
        this.state = nextStateGenerator.encrypt("0".getBytes());
        return otsSeedGenerator.encrypt("1".getBytes());
    }

    public byte[] nextSeed(){
        this.state = nextStateGenerator.encrypt("0".getBytes());
        return this.state;
    }

    public byte[] getValue(){
        return otsSeedGenerator.encrypt("1".getBytes());
    }

}
