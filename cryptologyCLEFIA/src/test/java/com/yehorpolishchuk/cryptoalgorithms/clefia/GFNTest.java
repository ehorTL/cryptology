package com.yehorpolishchuk.cryptoalgorithms.clefia;
import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;

import jdk.nashorn.internal.ir.Block;
import org.junit.Test;

import static org.junit.Assert.*;

public class GFNTest {

    private static byte[] keyBytes16 = new byte[]{
            -1, -18, -35, -52, -69, -86, -103, -120, 119, 102, 85, 68, 51, 34, 17, 0
    };

    private static byte[] plaintextBytes16 = new byte[]{
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };

    private final byte[][] roundKeys = {
            {-13,-26,-50,-7},{-115,-9,94,56},
            {65,-64,98,86},{100,10,-59,27},
            {106,39,-30,10},{90,121,27,-112},
            {-24,-59,40,-36},{0,51,110,-93},
            {89,-51,23,-60},{40,86,85,-125},
            {49,42,55,-52},{-64,-118,-67,119},
            {126,-114,126,-20},{-117,-25,-23,73},
            {-45,-12,99,-42},{-96,-86,-42,-86},
            {-25,94,-80,57},{13,101,126,-71},
            {1,-128,2,-30},{-111,23,-48,9},
            {-97,-104,-47,30},{-70,-66,-24,-49},
            {-80,54,-98,-6},{-45,-86,-17,13},
            {52,56,-7,59},{-7,-50,-92,-96},
            {104,-33,-112,41},{-72,105,-76,-89},
            {36,-42,64,109},{-25,75,-59,80},
            {65,-62,-127,-109},{22,-34,71,-107},
            {-93,74,32,-11},{51,38,93,20},
            {-79,-99,5,84},{81,66,-12,52},
    };

    @Test
    public void GFN4REncrypt() throws CryptoException {
        Block32[] fourBlockInput = {
            new Block32(new byte[]{-1, -18, -35, -52}),
            new Block32(new byte[]{-69, -86, -103, -120}),
            new Block32(new byte[]{119, 102, 85, 68}),
            new Block32(new byte[]{51, 34, 17, 0})
        };
        Block32[] roundKeysBlock = new Block32[36];
        for (int i = 0; i < 36; i++) {
            roundKeysBlock[i] = new Block32(roundKeys[i]);
        }

        Block128 actual = GFN.GFN4REncrypt(fourBlockInput, 18, roundKeysBlock);
        byte[] bytesExpected = {100, 57, -37, 127, -78, -38, -70, 103, 37, -58, 25, -122, -85, -55, 19, 109};
        assertArrayEquals(bytesExpected, actual.getBits128());
    }

    @Test
    public void GFN4RDecrypt() throws CryptoException {
        Block32[] fourBlockInput = {
                new Block32(new byte[]{100, 57, -37, 127}),
                new Block32(new byte[]{-78, -38, -70, 103}),
                new Block32(new byte[]{37, -58, 25, -122}),
                new Block32(new byte[]{-85, -55, 19, 109})
        };
        Block32[] roundKeysBlock = new Block32[36];
        for (int i = 0; i < 36; i++) {
            roundKeysBlock[i] = new Block32(roundKeys[i]);
        }

        Block128 actual = GFN.GFN4RDecrypt(fourBlockInput, 18, roundKeysBlock);
        byte[] bytesExpected = {-1, -18, -35, -52, -69, -86, -103, -120,119, 102, 85, 68, 51, 34, 17, 0};
        assertArrayEquals(bytesExpected, actual.getBits128());
    }

    @Test
    public void block32ToInt() throws CryptoException {
        Block32 b1 = new Block32(new byte[]{8,16,32,1});
        Block32 b2 = new Block32(new byte[]{0,0,65,12});
        int b1Actual = GFN.block32ToInt(b1);
        int b2Actual = GFN.block32ToInt(b2);
        assertEquals(135274497, b1Actual);
        assertEquals(16652, b2Actual);
    }

    @Test
    public void f0Function() throws CryptoException {
        //test case from specification
        Block32 actual = GFN.f0Function(new Block32(new byte[]{plaintextBytes16[0], plaintextBytes16[1], plaintextBytes16[2], plaintextBytes16[3]}),
                new Block32(roundKeys[0]));
        assertArrayEquals(new byte[]{84,122,49,-109}, actual.getBits32());

    }

    @Test
    public void f1Function() throws CryptoException {
        //test case from specification
        Block32 actual = GFN.f1Function(new Block32(new byte[]{plaintextBytes16[8], plaintextBytes16[9], plaintextBytes16[10], plaintextBytes16[11]}),
                new Block32(roundKeys[1]));
        assertArrayEquals(new byte[]{-85, -15, 32, 112}, actual.getBits32());
    }

    @Test
    public void s0Function() throws CryptoException {
        byte[] actual = new byte[4];
        actual[0] = GFN.s0Function((byte) -13);
        actual[1] = GFN.s0Function((byte) -25);
        actual[2] = GFN.s0Function((byte) -52);
        actual[3] = GFN.s0Function((byte) -6);

        byte[] expected = new byte[4];
        expected[0] = 41;
        expected[1] = 56;
        expected[2] = 70;
        expected[3] = 16;
        assertArrayEquals(expected, actual);
    }

    @Test
    public void s1Function() throws CryptoException {
        byte[] actual = new byte[4];
        actual[0] = GFN.s1Function((byte) -123);
        actual[1] = GFN.s1Function((byte) -2);
        actual[2] = GFN.s1Function((byte) 84);
        actual[3] = GFN.s1Function((byte) 51);

        byte[] expected = new byte[4];
        expected[0] = 119;
        expected[1] = -107;
        expected[2] = -24;
        expected[3] = 63;
        assertArrayEquals(expected, actual);
    }

    @Test
    public void m0Function() throws CryptoException {
        byte[] input = new byte[]{41,2,70,-31};
        Block32 actual = GFN.m0Function(input);
        byte[] expected = new byte[] {84,122,49,-109};
        assertArrayEquals(expected, actual.getBits32());
    }

    @Test
    public void m1Function() throws CryptoException {
        byte[] input = new byte[]{119,125,-24,-24};
        Block32 actual = GFN.m1Function(input);
        byte[] expected = new byte[] {-85,-15,32,112};
        assertArrayEquals(expected, actual.getBits32());
    }
}