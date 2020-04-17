package com.yehorpolishchuk.cryptology.elgamal;

import java.math.BigInteger;
import java.util.Date;
import java.util.Random;

public class Key {
    private static final int CERTAINTY = 90;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public Key(PublicKey publicKey, PrivateKey privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * Generates a key for ElGamal encryption scheme.
     * The key consists of public and private keys.
     *
     * Generates prime number "p" of (keyBitLength) bitlength.
     * Computes the smallest primitive root modulo p, called "g", g < p.
     * Takes random "x" < p.
     * Computes y = (g ^ x) mod p
     * The public key is {y, g, p}.
     * The private key is {x}.
     *
     * If you going to encrypt char,  8 <= keyBitLength.
     * It is strongly not recommended to use a keyBitLength greater than 20 (work time indefinite).
     * ElGamal encryption scheme can encrypt the message of at maximum (keyBitLength - 1) bits length per time.
     *
     * @param keyBitLength - a bitlength of prime "p" generated as a part of public key component,
     *                      3 < keyBitLength < 20
     * */
    public static Key generateKey(int keyBitLength) throws Exception {
        Random random = new Random(new Date().getTime());
        BigInteger p = new BigInteger(keyBitLength, CERTAINTY, random);
        BigInteger g = primitiveRootModulo(p);
        BigInteger x = new BigInteger(keyBitLength - 1, CERTAINTY, new Random(new Date().getTime()));
        BigInteger y = g.modPow(x, p);

        return new Key(new PublicKey(y, g, p), new PrivateKey(x));
    }

    /**
     * Finds g so that g ^ phi(p) mod p = 1
     * For prime "p": euler function phi(p) = p - 1.
     * For each i:  1 <= i <= phi(p) ->   (g^i) mod p != 1
     *
     * @return g
     * */
    private static BigInteger primitiveRootModulo(BigInteger p) throws Exception {
        BigInteger eulerFucntionValue = p.subtract(BigInteger.ONE);
        BigInteger i = BigInteger.ZERO;
        while(i.compareTo(eulerFucntionValue) <= 0){
            if (i.modPow(eulerFucntionValue, p).compareTo(BigInteger.ONE) == 0){
                return i;
            }
            i = i.add(BigInteger.ONE);
        }

        throw new Exception("NOT FOUND");
    }


    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
