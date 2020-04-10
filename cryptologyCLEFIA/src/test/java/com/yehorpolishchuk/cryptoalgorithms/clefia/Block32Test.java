package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import org.graalvm.compiler.phases.schedule.BlockClosure;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class Block32Test {

    private static final byte[] block32Bytes1 = {1,2,3,4};
    private static final byte[] block32Bytes2 = {5,6,7,8};
    private static final byte[] block32Bytes3 = {9,10,11,12};
    private static final byte[] block32Bytes4 = {0, -100, (byte)255, (byte)255};

    @Test(expected = CryptoException.class)
    public void block32ConstructorCryptoExceptionNullArg() throws Exception{
        new Block32(null);
    }

    @Test(expected = CryptoException.class)
    public void block32ConstructorCryptoExceptionArgSize() throws Exception{
        new Block32(new byte[]{1,2,3});
    }

    @Test
    public void getBits32() throws CryptoException {
        Block32[] blocks = new Block32[4];
        blocks[0] = new Block32(block32Bytes1);
        blocks[1] = new Block32(block32Bytes2);
        blocks[2] = new Block32(block32Bytes3);
        blocks[3] = new Block32(block32Bytes4);

        assertArrayEquals(block32Bytes1, blocks[0].getBits32());
        assertArrayEquals(block32Bytes2, blocks[1].getBits32());
        assertArrayEquals(block32Bytes3, blocks[2].getBits32());
        assertArrayEquals(block32Bytes4, blocks[3].getBits32());
    }

    @Test
    public void xor() throws CryptoException {
        Block32[] blocks = new Block32[3];
        blocks[0] = new Block32(block32Bytes1);
        blocks[1] = new Block32(block32Bytes2);
        blocks[2] = new Block32(block32Bytes3);

        byte[] expectedXor1 = new byte[]{4, 4, 4, 12};
        byte[] expectedXor2 = new byte[]{12,12,12,4};
        byte[] expectedXor3 = new byte[]{8,8,8,8};

        assertArrayEquals(expectedXor1, blocks[0].xor(blocks[1]).getBits32());
        assertArrayEquals(expectedXor2, blocks[1].xor(blocks[2]).getBits32());
        assertArrayEquals(expectedXor3, blocks[2].xor(blocks[0]).getBits32());
    }
}