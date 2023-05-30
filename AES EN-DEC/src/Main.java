public class Main {
    public static void main(String[] args) {

        try {
            String password = "@Mhmd@mrayje.com12345@";
            String plaintext = "TEST";
            System.out.println("Original Text: " + plaintext);

            // Encrypt the plaintext
            String encryptedText = AES.encrypt(plaintext, password);
            System.out.println("Encrypted Text: " + encryptedText);

            // Decrypt the encrypted text
            String decryptedText = AES.decrypt(encryptedText, password);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}