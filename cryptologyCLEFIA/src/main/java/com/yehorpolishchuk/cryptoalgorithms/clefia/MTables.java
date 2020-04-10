package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;

public class MTables {
    public static final int MATRIX_SIZE = 4;

    private static final byte[][] m0Matrix = {
            {0x01, 0x02, 0x04, 0x06},
            {0x02, 0x01, 0x06, 0x04},
            {0x04, 0x06, 0x01, 0x02},
            {0x06, 0x04, 0x02, 0x01}
    };

    private static final byte[][] m1Matrix = {
            {0x01, 0x08, 0x02, 0x0a},
            {0x08, 0x01, 0x0a, 0x02},
            {0x02, 0x0a, 0x01, 0x08},
            {0x0a, 0x02, 0x08, 0x01}
    };

    public static byte getM0Byte(int i, int j) throws CryptoException {
        if (i < 0 || i >= m0Matrix.length || j < 0 || j >= m0Matrix[i].length){
            throw new CryptoException("Index out of bound exception");
        }
        return m0Matrix[i][j];
    }

    public static byte getM1Byte(int i, int j) throws CryptoException {
        if (i < 0 || i >= m1Matrix.length || j < 0 || j >= m1Matrix[i].length){
            throw new CryptoException("Index out of bound exception");
        }
        return m1Matrix[i][j];
    }
}
