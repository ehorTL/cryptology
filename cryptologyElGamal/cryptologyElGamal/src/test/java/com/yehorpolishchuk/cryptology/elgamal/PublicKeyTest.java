package com.yehorpolishchuk.cryptology.elgamal;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class PublicKeyTest {
    private final BigInteger expectedP1 = new BigInteger("2789328934982349279292358597292040");
    private final BigInteger expectedY1 = new BigInteger("278932893498234927925859729112112134");
    private final BigInteger expectedG1 = new BigInteger("27893289349823492792923585972897854858");

    private final BigInteger expected2 = new BigInteger("0");
    private PublicKey publicKey1, publicKey2;

    @Before
    public void setUp() throws Exception{
        publicKey1 = new PublicKey(expectedY1, expectedG1, expectedP1);
        publicKey2 = new PublicKey(expected2, expected2, expected2);
    }

    @Test
    public void getKeyY() {
        assertTrue(expectedY1.compareTo(publicKey1.getKeyY()) == 0);
        assertTrue(expected2.compareTo(publicKey2.getKeyY()) == 0);
    }

    @Test
    public void getKeyG() {
        assertTrue(expectedG1.compareTo(publicKey1.getKeyG()) == 0);
        assertTrue(expected2.compareTo(publicKey2.getKeyG()) == 0);
    }

    @Test
    public void getKeyP() {
        assertTrue(expectedP1.compareTo(publicKey1.getKeyP()) == 0);
        assertTrue(expected2.compareTo(publicKey2.getKeyP()) == 0);
    }
}