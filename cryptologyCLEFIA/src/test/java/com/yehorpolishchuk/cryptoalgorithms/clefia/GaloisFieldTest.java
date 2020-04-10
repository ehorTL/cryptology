package com.yehorpolishchuk.cryptoalgorithms.clefia;

import org.junit.Test;

import static org.junit.Assert.*;

public class GaloisFieldTest {

    @Test
    public void multiplyGalois() {
        assertEquals(27, GaloisField.multiplyGalois((byte)5,(byte)7));
        assertEquals(27, GaloisField.multiplyGalois((byte)7,(byte)5));
        assertEquals(-125, GaloisField.multiplyGalois((byte)100, (byte)20));
        assertEquals( -125, GaloisField.multiplyGalois((byte)20, (byte)100));
        assertEquals(23, GaloisField.multiplyGalois((byte)14,(byte)55));
        assertEquals(-50, GaloisField.multiplyGalois((byte)26,(byte)64));
        assertEquals(-15, GaloisField.multiplyGalois((byte)127,(byte)127));
    }

    @Test
    public void xor() {
        assertArrayEquals(new byte[]{(byte)255,0}, GaloisField.xor(new byte[]{(byte)255,(byte)63},new byte[]{0,63}));
        assertArrayEquals(new byte[]{(byte)7,15}, GaloisField.xor(new byte[]{(byte)15,(byte)8},new byte[]{8,7}));
        assertArrayEquals(new byte[]{(byte)0,0}, GaloisField.xor(new byte[]{(byte)127,(byte)0},new byte[]{127,0}));
    }

    @Test
    public void findHighestSetBit() {
        assertEquals(14, GaloisField.findHighestSetBit(new byte[]{127, 8}));
        assertEquals(8, GaloisField.findHighestSetBit(new byte[]{1, 66}));
        assertEquals(2, GaloisField.findHighestSetBit(new byte[]{0, 7}));
    }
}