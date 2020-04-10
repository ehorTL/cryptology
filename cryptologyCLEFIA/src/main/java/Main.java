import com.yehorpolishchuk.cryptoalgorithms.clefia.*;
import com.yehorpolishchuk.cryptoalgorithms.exceptions.CryptoException;

public class Main {
    public static void main(String[] args) throws CryptoException {
        Block128 data = new Block128(new String("Hello, Im YEHOR!").getBytes());
        Block128 key = new Block128(new String("Hello, Im YULIA!").getBytes());

        Block128 ciphertext = Encryptor.encrypt(data, key);
        Block128 decrypted = Encryptor.decrypt( ciphertext, key);

        System.out.println(new String(data.getBits128()));
        System.out.println(new String(ciphertext.getBits128()));
        System.out.println(new String(decrypted.getBits128()));
    }
}

