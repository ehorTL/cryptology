package com.yehorpolishchuk.cryptology.elgamal;

import org.junit.Test;

import static org.junit.Assert.*;

public class EncryptorTest {

    @Test
    public void encryptDecryptString() throws Exception {
        String testString = "I am a test string";
        Encryptor encryptor = new Encryptor(Key.generateKey(8));
        assertEquals(testString, encryptor.decryptString(encryptor.encryptString(testString)));
    }

    @Test
    public void encryptDecrypt() throws Exception {
        Encryptor charEncryptor1 = new Encryptor(Key.generateKey(8));
        Encryptor encryptor2 = new Encryptor(Key.generateKey(20));
        byte[] expectedData1 = new byte[]{127};
        byte[] expectedData2 = new byte[]{15,64};

        assertArrayEquals(expectedData1, charEncryptor1.decrypt(charEncryptor1.encrypt(expectedData1)));
        assertArrayEquals(expectedData2, encryptor2.decrypt(encryptor2.encrypt(expectedData2)));
    }
}