package security;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAEncryption
{
    public static final String ALGORITHM_STRING = "RSA";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSAEncryption.ALGORITHM_STRING);
        return generator.generateKeyPair();
    }

    private static Cipher getCipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException
    {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    public static byte[] encrypt(byte[] message, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public static byte[] encrypt(byte[] message, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public static byte[] decrypt(byte[] cipherText, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public static byte[] decrypt(byte[] cipherText, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public static PrivateKey decodePrivateKey(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        return KeyFactory.getInstance(RSAEncryption.ALGORITHM_STRING).generatePrivate(new PKCS8EncodedKeySpec(data));
    }

    public static PublicKey decodePublicKey(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        return KeyFactory.getInstance(RSAEncryption.ALGORITHM_STRING).generatePublic(new X509EncodedKeySpec(data));
    }

}
