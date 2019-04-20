import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import java.security.MessageDigest;
import java.util.Formatter;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Encryption {

    public KeyPair keyPair = null;
    public String hash;
    public Encryption() throws Exception{
        keyPair = generateKeyPair();
    }


    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public void gethashcode (String cipherText)throws NoSuchAlgorithmException{
        String password = cipherText;
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();

        Formatter formatter = new Formatter();
        for (byte b : digest) {
            formatter.format("%02x", b);
        }
        String myHash = formatter.toString();
        hash = myHash.toUpperCase();
    }

    public String doEncrypt() throws Exception {

        //Our secret message
        String message = "Hello Bob! I am Alice!";

        //Encrypt the message
        String cipherText = encrypt(message, keyPair.getPublic());
        gethashcode(cipherText);

        //givenPassword_whenHashing_thenVerifying(cipherText);
        return cipherText;

    }
}