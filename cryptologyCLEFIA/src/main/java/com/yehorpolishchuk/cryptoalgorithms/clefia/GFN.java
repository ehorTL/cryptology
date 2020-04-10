package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import jdk.nashorn.internal.ir.Block;

/**
 * Generalized Feistel network (GFN)
 * GFN (d, r) where d - branches quantity, r - round number
 * */
public class GFN {

    /**
     * GFN(4,r) - 4-branches GFN with varying round quantity and (2 x round quantity) round keys.
     * @param fourBlocks - 128-bit data to be encrypted
     * @param rounds - rounds number
     * @param roundKeys - round keys array of size 2*rounds
     * */
    public static Block128 GFN4REncrypt(Block32[] fourBlocks, int rounds, Block32[] roundKeys) throws CryptoException {
        Block32[] t = new Block32[4];
        for (int i = 0; i < 4 ; i++) {
            t[i] = new Block32(fourBlocks[i].getBits32());
        }

        for (int i = 0; i < rounds; i++) {
            t[1] = t[1].xor(f0Function(t[0], roundKeys[2 * i]));
            t[3] = t[3].xor(f1Function(t[2], roundKeys[2 * i + 1]));

            Block32[] tiCopies = new Block32[4];
            for (int j = 0; j < 4; j++) {
                tiCopies[j] = new Block32(t[j].getBits32());
            }
            t[0] = tiCopies[1];
            t[1] = tiCopies[2];
            t[2] = tiCopies[3];
            t[3] = tiCopies[0];
        }

        return new Block128(new Block32[]{t[3], t[0], t[1], t[2]});
    }

    /**
     * ~GFN(4,r) - 4-branches inverse GFN with varying round quantity and (2 x round quantity) round keys.
     * @param fourBlocks - 128-bit data to be dencrypted
     * @param rounds - rounds number
     * @param roundKeys - round keys array of size 2*rounds
     * */
    public static Block128 GFN4RDecrypt(Block32[] fourBlocks, int rounds, Block32[] roundKeys) throws CryptoException {
        Block32[] t = new Block32[4];
        for (int i = 0; i < 4 ; i++) {
            t[i] = new Block32(fourBlocks[i].getBits32());
        }

        for (int i = 0; i < rounds; i++) {
            t[1] = t[1].xor(f0Function(t[0], roundKeys[2 * (rounds - i) - 2]));
            t[3] = t[3].xor(f1Function(t[2], roundKeys[2 * (rounds - i) - 1]));

            Block32[] tiCopies = new Block32[4];
            for (int j = 0; j < 4; j++) {
                tiCopies[j] = new Block32(t[j].getBits32());
            }
            t[0] = tiCopies[3];
            t[1] = tiCopies[0];
            t[2] = tiCopies[1];
            t[3] = tiCopies[2];
        }

        return new Block128(new Block32[]{t[1], t[2], t[3], t[0]});
    }

    /**
     * @return integer (4 byte) value the Block32 wrapped 4-byte array represents
     * array[3] - higher bits, ... , array[0] - lower bits
     * */
    public static int block32ToInt(Block32 b){
        int res = 0;
        res |= (int)b.getBits32()[0] << 24;
        res |= (int)b.getBits32()[1] << 16;
        res |= (int)b.getBits32()[2] << 8;
        res |= (int)b.getBits32()[3];

        return res;
    }

    /**
     * F0 function of GFN
     * */
    public static Block32 f0Function(Block32 x, Block32 roundKey) throws CryptoException {
        Block32 t = roundKey.xor(x);
        byte t0 = s0Function(t.getBits32()[0]);
        byte t1 = s1Function(t.getBits32()[1]);
        byte t2 = s0Function(t.getBits32()[2]);
        byte t3 = s1Function(t.getBits32()[3]);

        return m0Function(new byte[]{t0, t1, t2, t3});
    }

    /**
     * F1 function of GFN
     * */
    public static Block32 f1Function(Block32 x, Block32 roundKey) throws CryptoException {
        Block32 t = roundKey.xor(x);
        byte t0 = s1Function(t.getBits32()[0]);
        byte t1 = s0Function(t.getBits32()[1]);
        byte t2 = s1Function(t.getBits32()[2]);
        byte t3 = s0Function(t.getBits32()[3]);

        return m1Function(new byte[]{t0, t1, t2, t3});
    }

    /**
     * Higher 4 bits is a number of the S1 matrix row, lower 4 bits is a number of the S1 matrix column.
     * The value from S0 table with specified index is returned
     * */
    public static byte s0Function(byte ti) throws CryptoException {
        int i = 0, j = 0;
        i = (ti & 240) >> 4;
        j = (ti & 15);
        return STables.getS0TableByte(i, j);
    }

    /**
     * Higher 4 bits is a number of the S1 matrix row, lower 4 bits is a number of the S1 matrix column.
     * The value from S1 table with specified index is returned
     * */
    public static byte s1Function(byte ti) throws CryptoException {
        int i = 0, j = 0;
        i = (ti & 240) >> 4;
        j = (ti & 15);
        return STables.getS1TableByte(i, j);
    }

    /**
     * Matrix on vector multiplication 4x4 * 4x1
     * Input array size is 4 byte (32bits)
     * @param ti - array of size 4, matrix M0 will be multiplied by the vector from left
     * @return 4-byte vector wrapped in Block32 as a product of multiplication.
     * */
    public static Block32 m0Function(byte[] ti) throws CryptoException {
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++) {
               res[i] ^= GaloisField.multiplyGalois(MTables.getM0Byte(i, j), ti[j]);
            }
        }
        return new Block32(res);
    }

    /**
     * Matrix on vector multiplication 4x4 * 4x1
     * Input array size is 4 byte (32bits)
     * @param ti - array of size 4, matrix M1 will be multiplied by the vector from left
     * @return 4-byte vector wrapped in Block32 as a product of multiplication.
     * */
    public static Block32 m1Function(byte[] ti) throws CryptoException {
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++) {
                res[i] ^= GaloisField.multiplyGalois(MTables.getM1Byte(i, j), ti[j]);
            }
        }
        return new Block32(res);
    }
}
