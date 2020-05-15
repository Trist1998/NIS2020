package security;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;


public class RSAEncryptionTest
{

    @Test
    public void encrypt() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException
    {
        String message = "This is the secret test message";

        KeyPair key = RSAEncryption.generateKeyPair();

        //Encryption
        byte[] encryptedMessage = RSAEncryption.encrypt(message.getBytes(), key.getPublic());

        //Decryption
        byte[] decryptedMessage = RSAEncryption.decrypt(encryptedMessage, key.getPrivate());

        System.out.println("Original Message -> " + message);
        System.out.print("Encrypted Message -> "); System.out.println(new String(encryptedMessage));
        System.out.print("Decrypted Message -> "); System.out.println(new String(decryptedMessage));

        assertEquals(message, new String(decryptedMessage));

        //Try decrypt with different key
        KeyPair differentKey = RSAEncryption.generateKeyPair();
        try
        {
            byte[] wrongKeyDecryptedMessage = RSAEncryption.decrypt(encryptedMessage, differentKey.getPrivate());
            assertNotEquals(message, wrongKeyDecryptedMessage);
        }
        catch (BadPaddingException ex)
        {
            System.out.println("Bad Padding caused by incorrect key");
        }
    }
}
