import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {

        try {
            // Generate a random AES key
            SecretKey secretKey = AES.generateAESKey();
            System.out.println("KEY: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            String plaintext = "Hello, World!";
            System.out.println("Original Text: " + plaintext);

            // Encrypt the plaintext
            String encryptedText = AES.encrypt(plaintext, secretKey);
            System.out.println("Encrypted Text: " + encryptedText);

            // Decrypt the encrypted text
            String decryptedText = AES.decrypt(encryptedText, secretKey);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}