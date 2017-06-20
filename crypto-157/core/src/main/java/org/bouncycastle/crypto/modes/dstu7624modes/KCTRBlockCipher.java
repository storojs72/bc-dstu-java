package org.bouncycastle.crypto.modes.dstu7624modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of DSTU7624 CTR mode
 */
public class KCTRBlockCipher implements BlockCipher {

    private byte[] iv;
    private byte[] ofbV;
    private byte[] ofbOutV;
    private boolean forEncryption;

    private BlockCipher engine;

    public KCTRBlockCipher(BlockCipher engine){
        this.engine = engine;
        this.iv = new byte[engine.getBlockSize()];
        this.ofbV = new byte[engine.getBlockSize()];
        this.ofbOutV = new byte[engine.getBlockSize()];
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        this.forEncryption = forEncryption;

        if (params instanceof ParametersWithIV){
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();
            int diff = this.iv.length - iv.length;

            Arrays.fill(this.iv, (byte)0);
            System.arraycopy(iv, 0, this.iv, diff, iv.length);
            params = ivParam.getParameters();
        }
        else {
            throw new IllegalArgumentException("Invalid parameter passed");
        }

        reset();

        if (params != null){
            engine.init(true, params);
            engine.processBlock(this.iv, 0, ofbV, 0);
        }
    }

    public String getAlgorithmName() {
        return engine.getAlgorithmName() + "/KCTR";
    }

    public int getBlockSize() {
        return engine.getBlockSize();
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {

        if (in.length - inOff < getBlockSize()){
            throw new DataLengthException("Input buffer too short");
        }
        if (out.length - outOff < getBlockSize()){
            throw new DataLengthException("Output buffer too short");
        }

        ofbV[0]++; // Defined in standard;

        engine.processBlock(ofbV, 0 ,ofbOutV, 0);

        for (int byteIndex = 0; byteIndex < getBlockSize(); byteIndex++){
            out[outOff + byteIndex] = (byte)(ofbOutV[byteIndex] ^ in[inOff + byteIndex]);
        }

        return getBlockSize();
    }

    public void reset() {
        System.arraycopy(this.iv, 0, ofbV, 0, this.iv.length);
        engine.reset();
    }
}
