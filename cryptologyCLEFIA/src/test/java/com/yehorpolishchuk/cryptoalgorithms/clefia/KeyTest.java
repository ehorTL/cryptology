package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import jdk.nashorn.internal.ir.Block;
import org.junit.Test;

import static org.junit.Assert.*;

public class KeyTest {

    private static byte[] keyBytes16 = new byte[]{
            -1, -18, -35, -52, -69, -86, -103, -120, 119, 102, 85, 68, 51, 34, 17, 0
    };

    private byte[] expectedLKey = {-113,-119,-90,27,-99,-71,-48,-13,-109,-26,86,39,-38,13,2,126};

    private static final int[] CON128 = {
            0xf56b7aeb, 0x994a8a42, 0x96a4bd75, 0xfa854521,
            0x735b768a, 0x1f7abac4, 0xd5bc3b45, 0xb99d5d62,
            0x52d73592, 0x3ef636e5, 0xc57a1ac9, 0xa95b9b72,
            0x5ab42554, 0x369555ed, 0x1553ba9a, 0x7972b2a2,
            0xe6b85d4d, 0x8a995951, 0x4b550696, 0x2774b4fc,
            0xc9bb034b, 0xa59a5a7e, 0x88cc81a5, 0xe4ed2d3f,
            0x7c6f68e2, 0x104e8ecb, 0xd2263471, 0xbe07c765,
            0x511a3208, 0x3d3bfbe6, 0x1084b134, 0x7ca565a7,
            0x304bf0aa, 0x5c6aaa87, 0xf4347855, 0x9815d543,
            0x4213141a, 0x2e32f2f5, 0xcd180a0d, 0xa139f97a,
            0x5e852d36, 0x32a464e9, 0xc353169b, 0xaf72b274,
            0x8db88b4d, 0xe199593a, 0x7ed56d96, 0x12f434c9,
            0xd37b36cb, 0xbf5a9a64, 0x85ac9b65, 0xe98d4d32,
            0x7adf6582, 0x16fe3ecd, 0xd17e32c1, 0xbd5f9f66,
            0x50b63150, 0x3c9757e7, 0x1052b098, 0x7c73b3a7
    };

    private final byte[][] expectedRoundKeys = {
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
    public void getCON128() {
        for (int i = 0; i < 40; i++) {
            assertEquals(CON128[i], Key.getCON128(i));
        }
    }

    @Test
    public void getCON128Block32() throws CryptoException {
        for (int i = 0; i < 40; i++) {
            assertArrayEquals(Key.intToByteArray4(CON128[i]), Key.getCON128Block32(i).getBits32());
        }
    }

    @Test
    public void generateRoundKeysFromKey36() throws CryptoException {
        Block32[] roundKeysActual = Key.generateRoundKeysFromKey36(new Block128(keyBytes16));
        for (int i = 0; i < 36; i++) {
            assertArrayEquals(expectedRoundKeys[i], roundKeysActual[i].getBits32());
        }
    }

    @Test
    public void doubleSwap() throws CryptoException {
        Block128 swappedActual = Key.doubleSwap(new Block128(keyBytes16));
        byte[] expectedSwappedBytes = {-9, 110, -26, 93, -43, 76, -60, 0, -2, -18, -52, -86, -120, 102, 68, 34};
        assertArrayEquals(expectedSwappedBytes, swappedActual.getBits128());
    }

    @Test
    public void generateLKeyFromKey() throws CryptoException {
        Block128 lKey = Key.generateLKeyFromKey(new Block128(keyBytes16));
        assertArrayEquals(expectedLKey, lKey.getBits128());
    }

    @Test
    public void generateWhiteningKeys4FromKey() throws CryptoException {
        Block32[] whiteningKeys = Key.generateWhiteningKeys4FromKey(new Block128(keyBytes16));
        byte[][] expectedWhiteningKeysBytes = {
                {-1, -18, -35, -52}, {-69, -86, -103, -120},
                {119, 102, 85, 68}, {51, 34, 17, 0}
        };
        assertArrayEquals(expectedWhiteningKeysBytes[0], whiteningKeys[0].getBits32());
        assertArrayEquals(expectedWhiteningKeysBytes[1], whiteningKeys[1].getBits32());
        assertArrayEquals(expectedWhiteningKeysBytes[2], whiteningKeys[2].getBits32());
        assertArrayEquals(expectedWhiteningKeysBytes[3], whiteningKeys[3].getBits32());
    }

    @Test
    public void generateRoundKeysRK() throws CryptoException {
        Block32[] roundKeysActual = Key.generateRoundKeysRK(new Block128(expectedLKey), new Block128(expectedLKey));
        for (int i = 0; i < 36; i++) {
            assertArrayEquals(roundKeysActual[i].getBits32(), roundKeysActual[i].getBits32());
        }
    }

    @Test
    public void intToByteArray4() {
        byte[][] expected = {
            {0, 19, -43, 122},
            {5, 39, 124, 9},
            {0, 19, 111, -119}
        };

        byte[][] actual = new byte[3][];
        actual[0] = Key.intToByteArray4(1299834);
        actual[1] = Key.intToByteArray4(86473737);
        actual[2] = Key.intToByteArray4(1273737);

        for (int i = 0; i < 3; i++) {
            assertArrayEquals(expected[i], actual[i]);
        }
    }
}