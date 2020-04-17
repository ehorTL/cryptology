package com.yehorpolishchuk.cryptology.elgamal;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class PrivateKeyTest {

    @Test
    public void getKey() {
        BigInteger expected1 = new BigInteger("2789328934982349279292358597292040");
        BigInteger expected2 = new BigInteger("0");
        PrivateKey privateKey1 = new PrivateKey(expected1);
        PrivateKey privateKey2 = new PrivateKey(expected2);

        assertTrue(expected1.compareTo(privateKey1.getKey()) == 0);
        assertTrue(expected2.compareTo(privateKey2.getKey()) == 0);

    }
}