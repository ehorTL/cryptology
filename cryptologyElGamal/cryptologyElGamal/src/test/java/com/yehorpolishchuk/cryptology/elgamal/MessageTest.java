package com.yehorpolishchuk.cryptology.elgamal;

import com.sun.javafx.scene.shape.MeshHelper;
import org.junit.Test;

import static org.junit.Assert.*;

public class MessageTest {
    private final byte[] inputA = {0,127, (byte)255};
    private final byte[] inputB = {0,127, (byte)255};

    @Test
    public void getA() {
        Message m = new Message(inputA, inputB);
        assertArrayEquals(inputA, m.getA());
    }

    @Test
    public void getB() {
        Message m = new Message(inputA, inputB);
        assertArrayEquals(inputB, m.getB());
    }
}