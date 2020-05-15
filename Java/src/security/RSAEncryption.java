package security;

import javax.crypto.*;
import java.security.*;

public class RSAEncryption
{
    public static final String ALGORITHM_STRING = "RSA";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    private static Cipher getCipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException
    {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    public static byte[] encrypt(String message, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] cipherText, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(cipherText));
    }

}
