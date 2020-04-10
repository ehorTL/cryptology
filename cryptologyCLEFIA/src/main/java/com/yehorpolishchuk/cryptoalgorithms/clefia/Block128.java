package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import jdk.nashorn.internal.ir.Block;

public class Block128 {
    private byte[] bits128;

    public Block128(byte[] bytes16) throws CryptoException {
        if ((bytes16 == null) || (bytes16.length != 16)){
            throw new CryptoException("Not relevant block size exception");
        }
        bits128 = bytes16.clone();
    }

    public Block128(Block32[] fourBlocksOrdered){
        bits128 = new byte[16];
        for (int i = 0; i < 16; i++) {
            bits128[i] = fourBlocksOrdered[i/4].getBits32()[i%4];
        }
    }

    public byte[] getBits128() {
        return bits128;
    }

    public Block32 getBlock32(int index) throws CryptoException {
        index = index % 4;
        return new Block32(new byte[]{bits128[index * 4], bits128[index * 4 + 1], bits128[index * 4 + 2], bits128[index * 4 + 3]});
    }

    public Block128 xor(Block128 b) throws CryptoException {
        byte[] res = new byte[16];
        for (int i = 0; i < 16; i++) {
            res[i] = (byte) (this.bits128[i] ^ b.bits128[i]);
        }

        return new Block128(res);
    }
}
