package com.signature.scheme.merkleTree;

import java.io.Serializable;

public class Node implements Serializable {

    public int height;
    public final byte[] value;
    public int index;

    public Node(int height, byte[] value, int index) {
        this.height = height;
        this.value = value;
        this.index = index;
    }
}
