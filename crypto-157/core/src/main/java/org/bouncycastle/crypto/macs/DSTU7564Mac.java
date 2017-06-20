package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * Implementation of DSTU7564 MAC mode
 */
public class DSTU7564Mac implements Mac {
    private static final int BITS_IN_BYTE = 8;

    private DSTU7564Digest engine;

    private int macSize;

    private byte[] paddedKey;
    private byte[] invertedKey;
    private byte[] paddedIn;


    public DSTU7564Mac(int macBitSize){
        /* Mac size can be only 256 / 384 / 512. Same as hash size for DSTU7654Digest */
        this.engine = new DSTU7564Digest(macBitSize);
        this.macSize = macBitSize / BITS_IN_BYTE;

        this.paddedKey = null;
        this.invertedKey = null;
        this.paddedIn = null;
    }


    public void init(CipherParameters params) throws IllegalArgumentException {
        if (params instanceof KeyParameter){
            byte[] key = ((KeyParameter) params).getKey();

            invertedKey = new byte[key.length];

            paddedKey = pad(key, 0, key.length);

            for (int byteIndex = 0; byteIndex < invertedKey.length; byteIndex++){
                invertedKey[byteIndex] = (byte)(key[byteIndex] ^ (byte)0xFF);
            }
        }
        else {
            throw new IllegalArgumentException("Bad parameter passed");
        }
    }

    public String getAlgorithmName() {
        return "DSTU7564Mac";
    }

    public int getMacSize() {
        return macSize;
    }

    public void update(byte in) throws IllegalStateException {
        throw new NotImplementedException();
    }

    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        if (in.length - inOff < len){
            throw new DataLengthException("Input buffer too short");
        }

        if (paddedKey == null){
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }

        paddedIn = pad(in, inOff, len);

        byte[] result = new byte[paddedKey.length + paddedIn.length + invertedKey.length];
        System.arraycopy(paddedKey, 0, result, 0, paddedKey.length);
        System.arraycopy(paddedIn, 0, result, paddedKey.length, paddedIn.length);
        System.arraycopy(invertedKey, 0, result, paddedKey.length + paddedIn.length, invertedKey.length);

        engine.update(result, 0, result.length);
    }

    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (out.length - outOff < macSize){
            throw new DataLengthException("Output buffer too short");
        }
        if (paddedKey == null){
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }
        return engine.doFinal(out, outOff);
    }

    public void reset() {
        engine.reset();
    }

    private byte[] pad(byte[] in, int inOff, int len) {

        byte[] padded;
        if (len % engine.getBlockSize() == 0){
            padded = new byte[len + engine.getBlockSize()];
        }
        else {
            int blocks = len / engine.getBlockSize();
            padded = new byte[(blocks * engine.getBlockSize()) + engine.getBlockSize()];
        }

        System.arraycopy(in, inOff, padded, 0, len);

        padded[len] = (byte)0x80; // Defined in standard;
        intToBytes(len * BITS_IN_BYTE, padded, padded.length - 12); // Defined in standard;

        return padded;
    }

    private void intToBytes(int num, byte[] outBytes, int outOff){
        outBytes[outOff + 3] = (byte)(num >> 24);
        outBytes[outOff + 2] = (byte)(num >> 16);
        outBytes[outOff + 1] = (byte)(num >> 8);
        outBytes[outOff] = (byte)num;
    }
}
