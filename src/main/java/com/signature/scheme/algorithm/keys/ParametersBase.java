package com.signature.scheme.algorithm.keys;

import com.signature.scheme.algorithm.tools.HelperFunctions;

import java.io.Serializable;

import static com.signature.scheme.algorithm.tools.HelperFunctions.*;

/**
 * Class that holds parameters of digital signature algorithm
 */
public class ParametersBase implements Serializable {
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
    public int kU = 4;
    //Path Computation Algorithm parameter k for lower tree, such that internalH - kL is even and ((internalH-kU)/2) + 1 <= pow(2,internalH-kL+1)
    public int kL = 4;
    public int upperH = 10;
    public int lowerH = 10;
    public long signaturesNumber;
    public int maxH;
    public byte[][] bitmaskMain;
    public byte[][] bitmaskLTree;
    //Winternitz parameter for upper tree
    public int wU = 16;
    //Winternitz parmeter for lower tree
    public int wL = 16;
    public byte[] X;
    public byte[] seed;
    public byte[] hashFunctionKey;
    public int treeGrowth = 0;
    public int nextH;
    public long nextSize;
    public long lowerSize;
    public int initialLowerSize;
    public int upperSize;

    public ParametersBase(int m, int n, int kU, int kL, int upperH, int lowerH, int wL, int wU, byte[] x, int treeGrowth) {
        if ((((upperH - kU) / 2) + 1) > (Math.pow(2, (lowerH - kL + 1)))) {
            System.out.println("ERROR KL AND KU");
        }
        this.treeGrowth = treeGrowth;
        this.m = m;
        this.n = n;
        this.kU = kU;
        this.kL = kL;

        this.initialLowerSize = lowerH;
        this.upperH = upperH;
        this.lowerH = lowerH;
        this.upperSize = (int) Math.pow(2, upperH);
        setTreeSizees(lowerH, treeGrowth, upperH);

        this.wL = wL;
        this.wU = wU;
        this.X = x;

        setLengths(m, n, wL, wU);
        this.bitmaskMain = generateBitmask(maxH, false, n);
        this.bitmaskLTree = generateBitmask(maxL, true, n);
        byte[] hashFunctionKey = new byte[n];
        HelperFunctions.fillBytesRandomly(hashFunctionKey);
        this.hashFunctionKey = hashFunctionKey;

        if (treeGrowth == 1)
            this.signaturesNumber = (long) (Math.pow(2, lowerH + upperSize - 1) - Math.pow(2, lowerH));
        else
            this.signaturesNumber = ((upperSize - 1) * lowerSize);
    }

    public ParametersBase() {
        setLengths(m, n, wL, wU);
        if ((((upperH - kU) / 2) + 1) > (Math.pow(2, (lowerH - kL + 1)))) {
            System.out.println("ERROR KL AND KU");
        }
        this.X = KeysKeeper.generateX(n);
        this.seed = new byte[n];

        this.initialLowerSize = lowerH;
        this.upperSize = (int) Math.pow(2, upperH);
        setTreeSizees(lowerH, treeGrowth, upperH);

        bitmaskMain = generateBitmask(maxH, false, n);
        bitmaskLTree = generateBitmask(maxL, true, n);
        HelperFunctions.fillBytesRandomly(seed);
        byte[] hashFunctionKey = new byte[n];
        HelperFunctions.fillBytesRandomly(hashFunctionKey);
        this.hashFunctionKey = hashFunctionKey;
        if (treeGrowth == 1)
            this.signaturesNumber = (long) (Math.pow(2, lowerH + upperSize - 1) - Math.pow(2, lowerH));
        else
            this.signaturesNumber = ((upperSize - 1) * lowerSize);
    }

    public ParametersBase(int m, int n, int upperH, int lowerH, int wU, int wL, int treeGrowth, byte[] hashFunctionKey) {
        this.treeGrowth = treeGrowth;
        this.m = m;
        this.n = n;
        this.initialLowerSize = lowerH;
        this.upperH = upperH;
        this.lowerH = lowerH;
        this.wL = wL;
        this.wU = wU;
        int temp = (int) (lowerH + (Math.pow(2, upperH) - 2) * treeGrowth);
        this.maxH = Math.max(upperH, temp);
        setLengths(m, n, wL, wU);
        this.hashFunctionKey = hashFunctionKey;
    }

    public void setTreeSizees(int lowerH, int treeGrowth, int upperH) {
        this.nextH = lowerH + treeGrowth;
        this.lowerSize = (int) Math.pow(2, lowerH);
        this.nextSize = (int) (this.lowerSize * Math.pow(2, treeGrowth));
        int temp = (int) (lowerH + (Math.pow(2, upperH) - 2) * treeGrowth);
        this.maxH = Math.max(upperH, temp);
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
