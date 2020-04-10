package com.yehorpolishchuk.cryptoalgorithms.clefia;

public class GaloisField {
    /**
     * Multiplication in GF(2^8) as defined
     * with primitive polynomial z^8 + z^4 + z^3 + z^2 + 1
     * The primitive polynomial is represented in bits as: 1 00011101
     * @param b1 - byte to be multiplied in GF(2^8);
     * @param b2 - byte to be multiplied in GF(2^8);
     * */
    public static byte multiplyGalois(byte b1, byte b2){
        return divideOnIrreduciblePolynomialGetRemainder(multiply(b1, b2));
    }

    /**
     * Polynomial multiplication in GF(2^8) without division by primitive polynomial,
     * so the output product can be larger than 2^8, but definitely less than 2bytes (2^16 - 1)
     * as the greates possible nu,bers to by multiplied are
     * (2^8 - 1) * (2^8 - 1) = 2^16 - 2*2^8 + 1 < 2^16 - 1
     *
     * Result is ordered as: higherByte[0] lowerByte[1]
     * Test data: (5, 7) -> 27
     *
     * @param b1 - byte to be multiplied in GF(2^8);
     * @param b2 - byte to be multiplied in GF(2^8)
     * */
    private static byte[] multiply(byte b1, byte b2){
        byte[] res = new byte[2];
        for (int i = 0; i < 8; i++){
            byte[] tmp = new byte[2];
            for (int j = 0; j < 8; j++){
                tmp[((i+j)<8) ? 1 : 0] |= (((b1 & (1<<i)) != 0) && ((b2 & (1 << j)) != 0)) ? (byte)(1 << ((i+j) % 8)) : (byte)0;
            }
            res[0] ^= tmp[0];
            res[1] ^= tmp[1];
        }
        return res;
    }



    /**
     * Test data: (64, {0, 12}) -> ;
     * */
    private static byte[] multiply(byte b1, byte[] twoBytes){
        byte[] res = new byte[2];
        for (int i = 0; i < 8; i++){
            byte[] tmp = new byte[2];

            for (int j = 0; j < 16; j++){
                if (i+j >= 16){
                    continue;
                }
                tmp[((i+j)<8) ? 1 : 0] |= (((b1 & (1<<i)) != 0) && ((twoBytes[j<8 ? 1 : 0] & (1 << j%8)) != 0)) ?
                        (byte)(1 << ((i+j) % 8)) : (byte)0;
            }
            res[0] ^= tmp[0];
            res[1] ^= tmp[1];
        }
        return res;
    }

    /**
     * @param twoBytesDividend - 2-byte size number to be divided by primitive polynomial in GF(2^8) : z^8 + z^4 + z^3 + z^2 + 1.
     * @return - remainder on division in GF(2^8).
     * The primitive polynomial is represented in bits as: 1 00011101
     * */
    private static byte divideOnIrreduciblePolynomialGetRemainder(byte[] twoBytesDividend){
        byte[] divisor = {1, 29};
        byte remainder = 0;
        byte res = 0;

        int highestSetBitDividend = findHighestSetBit(twoBytesDividend);
        int highestSetBitDivisor = findHighestSetBit(divisor);
        while((highestSetBitDividend >= highestSetBitDivisor) && (highestSetBitDividend != -1)){
            int degreeDifference = highestSetBitDividend - highestSetBitDivisor;
            byte mult = (byte) (1 << degreeDifference);
            res |= mult;
            twoBytesDividend = xor(twoBytesDividend, multiply(mult, divisor));

            highestSetBitDividend = findHighestSetBit(twoBytesDividend);
            highestSetBitDivisor = findHighestSetBit(divisor);
        }

        remainder = twoBytesDividend[1];
        return remainder;
    }

    /**
     * @param b1 - array of 2 bytes size;
     * @param b2 - array of 2 bytes size;
     * @return - "exclusive or" operation between arrays as ordered bit sets.
     * */
    public static byte[] xor(byte[] b1, byte[] b2){
        return new byte[]{(byte) (b1[0]^b2[0]), (byte) (b1[1]^b2[1])};
    }

    /**
     * Bits are numbered as 15 14 13 .... 3 2 1 0.
     * Bytes represent them as follows:
     * Bytes[0]{15 14 ... 9 8} Bytes[1]{7 6 ... 2 1 0}
     * Returns the number of the highest set bit.
     * Returns -1 if no one bit is set.
     **/
    public static int findHighestSetBit(byte[] twoBytes){
        int num = -1;
        for (int i = 15; i >=0; i--) {
            if ((( 1<< (i%8)) & twoBytes[(i >= 8) ? 0 : 1]) != 0){
                return i;
            }
        }
        return num;
    }
}
