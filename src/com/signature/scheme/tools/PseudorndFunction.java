package com.signature.scheme.tools;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

// {F_k : {0,1}^n -> {0,1}^n | K belong to {0,1}^n }
public class PseudorndFunction {
    public int n;
    private String algorithm;
    private SecretKeySpec secretKey;
    private Cipher cipher;
    private byte[] key;
    private IvParameterSpec ivParams;

    public PseudorndFunction(int n) {
        this.n = n;
        this.algorithm = "AES";
        try {
            this.cipher = Cipher.getInstance("AES/CFB8/NoPadding");
            byte[] iv = new byte[cipher.getBlockSize()];
            this.ivParams = new IvParameterSpec(iv);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public void setKey(byte[] myKey) {

        //   MessageDigest sha = null;
        //   key = myKey.getBytes("UTF-8");
        //   sha = MessageDigest.getInstance("SHA-1");
        //   key = sha.digest(key);
        //   key = Arrays.copyOf(key, 16);

        if (myKey.length == this.n) {
            this.key = myKey;
            secretKey = new SecretKeySpec(this.key, this.algorithm);
        } else {
            System.err.println("Invalid key length " + myKey.length + " , try with length " + n);
        }

    }

    public byte[] encrypt(byte[] x) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, ivParams);
            return cipher.doFinal(x);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public byte[] composeFunction(byte[] x, byte[] myKey, int howMany) {
        byte[] value = myKey;
        for (int i = 1; i <= howMany; i++) {
            setKey(value);
            value = encrypt(x);
        }
        return value;
    }

    public byte[] decrypt(byte[] x) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, ivParams);
            return cipher.doFinal(x);
            //POMYSL O BASE
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
