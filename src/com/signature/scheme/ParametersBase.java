package com.signature.scheme;

import com.signature.scheme.tools.HashFunction;
import com.signature.scheme.tools.HelperFunctions;

import static com.signature.scheme.tools.HelperFunctions.*;

public class ParametersBase {
    //msg length
    public int m = 32;
    public int lu1;
    public int lu2;
    public int lU;
    public int ll1;
    public int ll2;
    public int lL;
    public int maxL;
    //security parameter
    public int n = 16;
    //Path Computation Algorithm parameter k for upper tree, such that internalH - kU is even and ((internalH-kU)/2) + 1 <= pow(2,internalH-kL+1)
    public int kU=1;
    //Path Computation Algorithm parameter k for lower tree, such that internalH - kL is even and ((internalH-kU)/2) + 1 <= pow(2,internalH-kL+1)
    public int kL=2;
    public int upperH = 3;
    public int lowerH = 2;
    public int signaturesNumber;
    public int maxH;
    public byte[][] bitmaskMain;
    public byte[][] bitmaskLTree;
    //Winternitz parameter for upper tree
    public int wU=4;
    //Winternitz parmeter for lower tree
    public int wL=4;
    public byte[] X;
    public byte[] seed;
    public byte[] hashFunctionKey;
    public int treeGrowth = 1;
    public int nextH;
    public int nextSize;
    public int lowerSize;
    public int upperSize;

    public ParametersBase(int m, int n, int kU, int kL, int upperH, int lowerH, int wL, int wU, byte[] x, int treeGrowth) {
        this.treeGrowth = treeGrowth;
        this.m = m;
        this.n = n;
        this.kU = kU;
        this.kL = kL;
        this.upperH = upperH;
        this.lowerH = lowerH;
        this.nextH = lowerH + treeGrowth;
        this.lowerSize = (int) Math.pow(2,lowerH);
        this.upperSize = (int) Math.pow(2,upperH);
        this.nextSize = (int) (this.lowerSize*Math.pow(2,treeGrowth));
        int temp = (int) (lowerH + (Math.pow(2,upperH)-2)*treeGrowth);
        this.maxH = Math.max(upperH, temp);
        System.out.println(this.maxH + " KURDE " + temp + " " + upperH);
        this.wL = wL;
        this.wU = wU;
        this.X = x;

        setLengths(m, n, wL, wU);
        this.bitmaskMain = generateBitmask(maxH, false, n);
        this.bitmaskLTree = generateBitmask(maxL, true, n);
        byte[] hashFunctionKey = new byte[n];
        HelperFunctions.fillBytesRandomly(hashFunctionKey);
        this.hashFunctionKey = hashFunctionKey;

        this.signaturesNumber = (int) (Math.pow(2,lowerH + upperSize -1) - Math.pow(2,lowerH));
    }

    public ParametersBase() {
        setLengths(m, n, wL, wU);

        this.X = KeysKeeper.generateX(n);
        this.seed = new byte[n];
        this.nextH = lowerH + treeGrowth;
        this.lowerSize = (int) Math.pow(2,lowerH);
        this.upperSize = (int) Math.pow(2,upperH);
        this.nextSize = (int) (this.lowerSize*Math.pow(2,treeGrowth));
        int temp = (int) (lowerH + (Math.pow(2,upperH)-2)*treeGrowth);
        this.maxH = Math.max(upperH, temp);
        System.out.println(this.maxH + " KURDE " + temp + " " + upperH);
        bitmaskMain = generateBitmask(maxH, false, n);
        bitmaskLTree = generateBitmask(maxL, true, n);
        HelperFunctions.fillBytesRandomly(seed);
        byte[] hashFunctionKey = new byte[n];
        HelperFunctions.fillBytesRandomly(hashFunctionKey);
        this.hashFunctionKey = hashFunctionKey;
        this.signaturesNumber = (int) (Math.pow(2,lowerH + upperSize -1) - Math.pow(2,lowerH));
    }

    private void setLengths(int m, int n, int wL, int wU) {
        lu1 = (int) Math.ceil(n / log2(wU));
        lu2 = (int) Math.floor(log2(lu1 * (wU - 1)) / log2(wU));
        lU = lu1 + lu2;
        ll1 = (int) Math.ceil(m / log2(wL));
        ll2 = (int) Math.floor(log2(ll1 * (wL - 1)) / log2(wL));
        lL = ll1 + ll2;
        maxL = Math.max(lL, lU);
    }

    public static byte[][] generateBitmask(int treeSize, Boolean LTree, int n) {
        int size;
        if (LTree) {
            size = ceilLogTwo(treeSize);
        } else {
            size = treeSize;
        }
        byte[][] bitmasksArray = new byte[size][2 * n];

        for (int i = 0; i < size; i++) {
            fillBytesRandomly(bitmasksArray[i]);
        }
        return bitmasksArray;
    }
}
