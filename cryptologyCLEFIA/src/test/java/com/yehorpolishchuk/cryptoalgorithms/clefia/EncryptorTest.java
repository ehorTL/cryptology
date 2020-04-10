package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Test vectors from the official specification:
 * Key: ffeeddcc bbaa9988 77665544 33221100
 * Plaintext: 00010203 04050607 08090a0b 0c0d0e0f
 * Ciphertext: de2bf2fd 9b74aacd f1298555 459494fd
 */
public class EncryptorTest {
    private static byte[] keyBytes16 = new byte[]{
        -1, -18, -35, -52, -69, -86, -103, -120, 119, 102, 85, 68, 51, 34, 17, 0
    };

    private static byte[] plaintextBytes16 = new byte[]{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };

    private static byte[] ciphertextBytes16 = new byte[]{
        -34, 43, -14, -3, -101, 116, -86, -51, -15, 41, -123, 85, 69, -108, -108, -3
    };

    @Test
    public void encrypt() throws CryptoException {
        Block128 plaintextBlock = new Block128(plaintextBytes16);
        Block128 keyBlock = new Block128(keyBytes16);
        Block128 ciphertextBlockExpected = new Block128(ciphertextBytes16);
        Block128 ciphertextBlockActual = Encryptor.encrypt(plaintextBlock, keyBlock);
        assertArrayEquals(ciphertextBlockExpected.getBits128(), ciphertextBlockActual.getBits128());
    }

    @Test
    public void decrypt() throws CryptoException {
        Block128 plaintextBlock = new Block128(plaintextBytes16);
        Block128 keyBlock = new Block128(keyBytes16);
        Block128 ciphertextBlock = new Block128(ciphertextBytes16);
        Block128 plaintextBlockActual = Encryptor.decrypt(ciphertextBlock, keyBlock);
        assertArrayEquals(plaintextBlock.getBits128(), plaintextBlockActual.getBits128());
    }
}