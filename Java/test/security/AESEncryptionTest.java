package security;



import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.security.*;

import static org.junit.Assert.*;


public class AESEncryptionTest
{

    @Test
    public void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException
    {
        String message = "This is the secret test message";

        Key key = AESEncryption.generateKey();
        IvParameterSpec ivParameterSpec = AESEncryption.getIvSpec();

        //Encryption
        byte[] encryptedMessage = AESEncryption.encrypt(message, key, ivParameterSpec);

        //Decryption
        String decryptedMessage = AESEncryption.decrypt(encryptedMessage, key, ivParameterSpec);

        System.out.println("Original Message -> " + message);
        System.out.print("Encrypted Message -> "); System.out.println(new String(encryptedMessage));
        System.out.println("Decrypted Message -> " + decryptedMessage);

        assertEquals(message, decryptedMessage);

        //Try decrypt with different key
        Key differentKey = AESEncryption.generateKey();
        String wrongKeyDecryptedMessage = "";
        try
        {
            wrongKeyDecryptedMessage = AESEncryption.decrypt(encryptedMessage, differentKey, ivParameterSpec);
            assertNotEquals(message, wrongKeyDecryptedMessage);
        }
        catch (BadPaddingException ex)
        {
            System.out.println("Bad Padding caused by incorrect key");
        }

    }

}
