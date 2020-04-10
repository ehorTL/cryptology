package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;

public class Key {
    public static final int CON128_TABLE_SIZE = 60;

    /**
     * Constant 60 32-bit primitive keys for 128-bit algorithm
     * For 196 and 256 -bit keys there must be other 84 and 92 -element tables respectively.
     */
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

    /**
     * Returns constant CON(128, i) integer (4-bytes) key for 128-bit CLEFIA algorithm
     * @param index - index of constant CON(128, index) key from table of 60 values, 0<=index<60
     */
    public static int getCON128(int index) {
        return CON128[index % CON128_TABLE_SIZE];
    }

    /**
     * Returns constant CON(128, i) key wrapped in Block32 for 128-bit CLEFIA algorithm
     * @param index - index of constant CON(128, index) key from table of 60 values, 0<=index<60
     * */
    public static Block32 getCON128Block32(int index) throws CryptoException {
        return new Block32(intToByteArray4(CON128[index % CON128_TABLE_SIZE]));
    }

    /**
     * For 128-bit CLEFIA algorithm returns 36 round keys (for 18 rounds used in algorithm),
     * 2 per one round
     * @return - array of 36 round keys for 128-bit CLEFIA algorithm
     * */
    public static Block32[] generateRoundKeysFromKey36(Block128 key) throws CryptoException {
        Block128 lKey = generateLKeyFromKey(key);
        return generateRoundKeysRK(lKey, key);
    }

    /**
     * Double swap operation reorders bits of 128bit block as follows:
     * {X[7-63]|X[121-127]|X[0-6]|X[64-120]}
     */
    public static Block128 doubleSwap(Block128 block) throws CryptoException {
        byte[] bytesInput = block.getBits128();
        byte[] result = new byte[16];
        //start with 0th end with 56th bit
        for (int i = 7; i <= 63; i++) {
            result[(i - 7) / 8] |= (((1 << (7 -(i % 8))) & bytesInput[i / 8]) != 0) ? (1 << ( 7 - (i-7)%8 )) : 0;
        }
        //start with 57th end with 63rd bit
        for (int i = 121; i <= 127; i++) {
            result[(i - 64) / 8] |= (((1 << (7 -(i % 8))) & bytesInput[i / 8]) != 0) ? (1 << ( 7 - (i-64)%8 )) : 0;
        }
        //start with 64th end with 70th bit
        for (int i = 0; i <= 6; i++) {
            result[(i + 64) / 8] |= (((1 << (7 -(i % 8))) & bytesInput[i / 8]) != 0) ? (1 << ( 7 - (i+64)%8 )) : 0;
        }
        //start with 71st end with 127th bit
        for (int i = 64; i <= 120; i++) {
            result[(i + 7) / 8] |= (((1 << (7 -(i % 8))) & bytesInput[i / 8]) != 0) ? (1 << ( 7 - (i+7)%8 )) : 0;
        }

        return new Block128(result);
    }

    /**
     * Generates L key for 128-bit CLEFIA algorithm from input key.
     * Use GFN (4,12): 4 - branches, 12 round and 24 constant keys CON.
     */
    public static Block128 generateLKeyFromKey(Block128 key) throws CryptoException {
        Block32[] con128Keys24 = new Block32[24];
        for (int i = 0; i < 24; i++) {
            con128Keys24[i] = new Block32(intToByteArray4(CON128[i]));
        }

        return GFN.GFN4REncrypt(new Block32[]{key.getBlock32(0), key.getBlock32(1),
                key.getBlock32(2), key.getBlock32(3)}, 12, con128Keys24);
    }

    /**
     * For 128bit CLEFIA algorithm generates whitening keys.
     * Whitening keys in this case are slices of input key in the
     * same order as in the input key the bytes are.
     * */
    public static Block32[] generateWhiteningKeys4FromKey(Block128 key) throws CryptoException {
        return new Block32[]{key.getBlock32(0), key.getBlock32(1), key.getBlock32(2), key.getBlock32(3)};
    }

    /**
     * Generates 36 round keys for 128bit-block CLEFIA algorithm
     * from the input key and L key (previously generated from input key)
     *
     * @param lKey - L key of CLEFIA 128-bit algorithm
     * @param key - input key of the CLEFIA algorithm
     * @return - 36-element array of 32-bit round keys for 128-bit CLEFIA algorithm
     * */
    public static Block32[] generateRoundKeysRK(Block128 lKey, Block128 key) throws CryptoException {
        Block32[] roundKeysOutput = new Block32[36];
        for (int i = 0; i < 9; i++) {
            Block128 t = lKey.xor(new Block128(new Block32[]{
                    getCON128Block32(24 + 4 * i),
                    getCON128Block32(24 + 4 * i + 1),
                    getCON128Block32(24 + 4 * i + 2),
                    getCON128Block32(24 + 4 * i + 3)
            }));

            //SIGMA notation S(L) is a doubleSwap function(L)
            lKey = doubleSwap(lKey);
            if (i % 2 == 1) {
                t = t.xor(key);
            }

            //copying the t value into 4 round keys with relevant indexes
            for (int j = 0; j < 4; j++) {
                roundKeysOutput[4 * i + j] = t.getBlock32(j);
            }
        }

        return roundKeysOutput;
    }

    /**
     * Converts 4-byte into byte array of size 4.
     * Higher bits are in returnValue[0], and lower are in the returnValue[3]
     * */
    public static byte[] intToByteArray4(final int data) {
        return new byte[]{
                (byte) ((data >> 24) & 0xff),
                (byte) ((data >> 16) & 0xff),
                (byte) ((data >> 8) & 0xff),
                (byte) ((data >> 0) & 0xff),
        };
    }
}
