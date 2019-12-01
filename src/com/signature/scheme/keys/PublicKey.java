package com.signature.scheme.keys;

import java.io.Serializable;

public class PublicKey implements Serializable {
    public byte[][] bitmaskLTree;
    public byte[][] bitmaskMain;
    public byte[] X;
    public byte[] upperRoot;
}
