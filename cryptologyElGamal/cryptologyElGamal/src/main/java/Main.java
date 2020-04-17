import com.yehorpolishchuk.cryptology.elgamal.*;

public class Main {
    public static void main(String[] args) throws Exception {
        Key key =  Key.generateKey(16);
        Encryptor encryptor = new Encryptor(key);

        String plaintext = "Hello Yehor, how are you?";
        System.out.println(encryptor.decryptString(encryptor.encryptString(plaintext)));
    }
}
