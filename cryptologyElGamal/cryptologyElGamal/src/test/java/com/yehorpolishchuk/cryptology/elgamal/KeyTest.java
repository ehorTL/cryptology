package com.yehorpolishchuk.cryptology.elgamal;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class KeyTest {

    @Test
    public void pKeyBitLength() throws Exception {
        Key key1 = Key.generateKey(4);
        Key key2 = Key.generateKey(10);
        Key key3 = Key.generateKey(16);
        Key key4 = Key.generateKey(20);

        assertEquals(4, key1.getPublicKey().getKeyP().bitLength());
        assertEquals(10, key2.getPublicKey().getKeyP().bitLength());
        assertEquals(16, key3.getPublicKey().getKeyP().bitLength());
        assertEquals(20, key4.getPublicKey().getKeyP().bitLength());
    }

    @Test
    public void gPrimitiveRootModuloP() throws Exception {
        Key[] keys = new Key[]{
            Key.generateKey(4),
            Key.generateKey(10),
            Key.generateKey(16),
            Key.generateKey(20)
        };

        for (int j = 0; j < 4; j++){
            BigInteger i = BigInteger.ONE;
            BigInteger product = BigInteger.ONE;
            for (; i.compareTo(keys[j].getPublicKey().getKeyP().subtract(BigInteger.ONE)) <= 0; i = i.add(BigInteger.ONE)){
                product = product.multiply(keys[j].getPublicKey().getKeyG());
            }

            assertTrue(product.mod(keys[j].getPublicKey().getKeyP()).compareTo(BigInteger.ONE) == 0);
        }
    }
}