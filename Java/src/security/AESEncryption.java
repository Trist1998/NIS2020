package security;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class AESEncryption
{
    public static final String ALGORITHM_STRING = "AES";

    public AESEncryption()
    {}

    private static Cipher getCipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException
    {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public static Key generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    public static IvParameterSpec getIvSpec() throws NoSuchAlgorithmException
    {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        return new IvParameterSpec(random);
    }

    public static byte[] encrypt(byte[] message, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public static byte[] decrypt(byte[] cipherText, Key key) throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }
}
