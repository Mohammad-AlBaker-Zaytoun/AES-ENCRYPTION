import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AES {
    private static final String AES_ALGORITHM = "AES";
    private static final String PBKDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int PBKDF_ITERATIONS = 10000;
    private static final int KEY_LENGTH_BITS = 256;

    public static SecretKey generateAESKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_ALGORITHM);
        byte[] salt = generateSalt();
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF_ITERATIONS, KEY_LENGTH_BITS);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), AES_ALGORITHM);
    }

    public static byte[] generateSalt() {
        // Generate a random salt
        // You can use a secure random number generator to generate the salt
        // Example: SecureRandom.getInstanceStrong().nextBytes(salt);
        return new byte[16];
    }

    public static String encrypt(String plaintext, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKey secretKey = generateAESKey(password);
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedText, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKey secretKey = generateAESKey(password);
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
