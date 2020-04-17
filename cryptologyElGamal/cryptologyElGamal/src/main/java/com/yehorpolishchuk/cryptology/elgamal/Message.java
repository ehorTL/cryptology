package com.yehorpolishchuk.cryptology.elgamal;

public class Message {
    private byte[] a;
    private byte[] b;

    public Message(byte[] a, byte[] b){
        this.a = a.clone();
        this.b = b.clone();
    }

    public byte[] getA() {
        return a;
    }

    public byte[] getB() {
        return b;
    }
}
