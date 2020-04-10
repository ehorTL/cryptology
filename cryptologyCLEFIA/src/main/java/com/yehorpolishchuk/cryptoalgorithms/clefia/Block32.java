package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;

public class Block32 {
    private byte[] bits32;

    public Block32(byte[] bytes4) throws CryptoException {
        if ((bytes4 == null) || (bytes4.length != 4)) {
            throw new CryptoException("Not relevant block size exception");
        }
        bits32 = bytes4.clone();
    }

    public byte[] getBits32() {
        return bits32;
    }

    public Block32 xor(Block32 b) throws CryptoException {
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++) {
            res[i] = (byte) (this.bits32[i] ^ b.bits32[i]);
        }
        return new Block32(res);
    }
}
