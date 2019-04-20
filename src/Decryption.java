import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Formatter;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Decryption {

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }


    public static String computeHash(String cipherText)
            throws NoSuchAlgorithmException {

        String password = cipherText;
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();

        Formatter formatter = new Formatter();
        for (byte b : digest) {
            formatter.format("%02x", b);
        }
        String myHash = formatter.toString();

        return myHash.toUpperCase();
    }

    public static void main(String[] args) throws Exception {
        Encryption e = new Encryption();
        String encryptedMessage = "";
        encryptedMessage = e.doEncrypt();

        //Now decrypt it
        String decipheredMessage = decrypt(encryptedMessage, e.keyPair.getPrivate());

        System.out.println("The message is: " + decipheredMessage);

        String hashFromEncryption = e.hash;
        if(hashFromEncryption.equals(computeHash(encryptedMessage))){
            System.out.println("Hash code is equal");

        }

    }
}