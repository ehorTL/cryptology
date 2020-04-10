package com.yehorpolishchuk.cryptoalgorithms.clefia;

import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;

public class Encryptor {

    public static Block128 encrypt (Block128 data, Block128 key) throws CryptoException{
        return encrypt128(data, key);
    }

    public static Block128 decrypt (Block128 encData, Block128 key) throws CryptoException {
        return decrypt128(encData, key);
    }

    /**
     * CLEFIA 128-bit encryption algorithm implementation.
     * Use 18 rounds and 36 32-bit round keys.
     * */
    private static Block128 encrypt128(Block128 data, Block128 key) throws CryptoException {
        final int rounds = 18;
        Block32[] whiteningKeys = Key.generateWhiteningKeys4FromKey(key);

        Block32[] Ti = new Block32[4];
        Ti[0] = data.getBlock32(0);
        Ti[1] = data.getBlock32(1).xor(whiteningKeys[0]);
        Ti[2] = data.getBlock32(2);
        Ti[3] = data.getBlock32(3).xor(whiteningKeys[1]);

        Block32[] roundKeys = Key.generateRoundKeysFromKey36(key);

        Block128 encrypted = GFN.GFN4REncrypt(new Block32[]{Ti[0],Ti[1],Ti[2],Ti[3]}, rounds, roundKeys);
        return new Block128(new Block32[]{encrypted.getBlock32(0), encrypted.getBlock32(1).xor(whiteningKeys[2]),
                encrypted.getBlock32(2), encrypted.getBlock32(3).xor(whiteningKeys[3])});
    }

    /**
     * CLEFIA 128-bit decryption algorithm implementation.
     * Use 18 rounds and 36 32-bit round keys.
     * */
    private static Block128 decrypt128(Block128 encData, Block128 key) throws CryptoException {
        final int rounds = 18;
        Block32[] whiteningKeys = Key.generateWhiteningKeys4FromKey(key);

        Block32[] Ti = new Block32[4];
        Ti[0] = encData.getBlock32(0);
        Ti[1] = encData.getBlock32(1).xor(whiteningKeys[2]);
        Ti[2] = encData.getBlock32(2);
        Ti[3] = encData.getBlock32(3).xor(whiteningKeys[3]);

        Block32[] roundKeys = Key.generateRoundKeysFromKey36(key);
        Block128 decrypted = GFN.GFN4RDecrypt(new Block32[]{Ti[0],Ti[1],Ti[2],Ti[3]}, rounds, roundKeys);
        return new Block128(new Block32[]{decrypted.getBlock32(0), decrypted.getBlock32(1).xor(whiteningKeys[0]),
                decrypted.getBlock32(2), decrypted.getBlock32(3).xor(whiteningKeys[1])});
    }
}
