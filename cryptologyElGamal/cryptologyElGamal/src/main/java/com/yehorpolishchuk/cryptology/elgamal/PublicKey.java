package com.yehorpolishchuk.cryptology.elgamal;

import java.math.BigInteger;

public class PublicKey {
    private BigInteger keyY, keyG, keyP;

    public PublicKey(BigInteger y, BigInteger g, BigInteger p){
        this.keyY = y;
        this.keyG = g;
        this.keyP = p;
    }

    public BigInteger getKeyY() {
        return keyY;
    }

    public BigInteger getKeyG() {
        return keyG;
    }

    public BigInteger getKeyP() {
        return keyP;
    }
}
