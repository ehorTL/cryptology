package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import org.junit.Test;

import static org.junit.Assert.*;

public class Block128Test {

    private final static byte[] block128Bytes1 = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    private final static byte[] block128Bytes2 = new byte[]{17,18,19,20,21,22,23,24,25,26,27,28,29,20,31,32};

    @Test(expected = CryptoException.class)
    public void block128ConstructorCryptoExceptionNullArg() throws CryptoException {
        new Block128((byte[]) null);
    }

    @Test(expected = CryptoException.class)
    public void block128ConstructorCryptoExceptionArgSize() throws CryptoException {
        new Block128(new byte[] {1,2,3});
    }

    @Test
    public void getBits128() throws CryptoException {
        Block128 block1 = new Block128(block128Bytes1);
        Block128 block2 = new Block128(block128Bytes2);
        assertArrayEquals(block128Bytes1, block1.getBits128());
        assertArrayEquals(block128Bytes2, block2.getBits128());
    }

    @Test
    public void getBlock32() throws CryptoException {
        Block128 block128 = new Block128(block128Bytes1);
        Block32 subblock0 = new Block32(new byte[]{block128Bytes1[0], block128Bytes1[1], block128Bytes1[2], block128Bytes1[3]});
        Block32 subblock1 = new Block32(new byte[]{block128Bytes1[4], block128Bytes1[5], block128Bytes1[6], block128Bytes1[7]});
        Block32 subblock2 = new Block32(new byte[]{block128Bytes1[8], block128Bytes1[9], block128Bytes1[10], block128Bytes1[11]});
        Block32 subblock3 = new Block32(new byte[]{block128Bytes1[12], block128Bytes1[13], block128Bytes1[14], block128Bytes1[15]});

        assertArrayEquals(subblock0.getBits32(), block128.getBlock32(0).getBits32());
        assertArrayEquals(subblock1.getBits32(), block128.getBlock32(1).getBits32());
        assertArrayEquals(subblock2.getBits32(), block128.getBlock32(2).getBits32());
        assertArrayEquals(subblock3.getBits32(), block128.getBlock32(3).getBits32());
    }

    @Test
    public void xor() throws CryptoException {
        Block128  block1 = new Block128(block128Bytes1);
        Block128  block2 = new Block128(block128Bytes2);
        Block128 blockXor = block1.xor(block2);
        byte[] expected = new byte[]{16,16,16,16,16,16,16,16,16,16,16,16,16,26,16,48};
        assertArrayEquals(expected, blockXor.getBits128());
    }
}