package security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class AESEncryption
{
    public AESEncryption()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static Cipher getCipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException
    {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public static Key generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    public static IvParameterSpec getIvSpec() throws NoSuchAlgorithmException
    {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");//Reason for this around 20:00 in this video https://www.youtube.com/watch?v=1925zmDP_BY
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        return new IvParameterSpec(random);
    }


    public static byte[] encrypt(String message, Key key, IvParameterSpec ivSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(message.getBytes());
    }

    public static byte[] encrypt(String message, Key key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        return encrypt(message.getBytes(), key);
    }

    public static byte[] encrypt(byte[] message, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public static String decrypt(byte[] cipherText, Key key, IvParameterSpec ivSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return new String(cipher.doFinal(cipherText));
    }

    public static String decrypt(byte[] cipherText, Key key) throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(cipherText));
    }
}
