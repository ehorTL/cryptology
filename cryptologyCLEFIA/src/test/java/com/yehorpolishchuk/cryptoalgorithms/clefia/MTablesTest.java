package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import org.junit.Test;

import static org.junit.Assert.*;

public class MTablesTest {

    @Test
    public void getM0Byte() throws CryptoException {
        byte[][] m0Matrix = {
            {0x01, 0x02, 0x04, 0x06},
            {0x02, 0x01, 0x06, 0x04},
            {0x04, 0x06, 0x01, 0x02},
            {0x06, 0x04, 0x02, 0x01}
        };
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                assertEquals(m0Matrix[i][j], MTables.getM0Byte(i, j));
            }
        }
    }

    @Test
    public void getM1Byte() throws CryptoException {
        byte[][] m1Matrix = {
            {0x01, 0x08, 0x02, 0x0a},
            {0x08, 0x01, 0x0a, 0x02},
            {0x02, 0x0a, 0x01, 0x08},
            {0x0a, 0x02, 0x08, 0x01}
        };

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                assertEquals(m1Matrix[i][j], MTables.getM1Byte(i, j));
            }
        }
    }
}