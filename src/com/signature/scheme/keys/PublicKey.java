package com.signature.scheme.keys;

import java.io.Serializable;

/**
 * Represents public key of the scheme.
 */
public class PublicKey implements Serializable {
    public byte[][] bitmaskLTree;
    public byte[][] bitmaskMain;
    public byte[] X;
    public byte[] upperRoot;
}
