package security;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;


public class RSAEncryptionTest
{

    @Test()
    public void testReadCertFromFile() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException
    {
        byte[] fileContent = Files.readAllBytes(Paths.get("C:\\Users\\trist\\IdeaProjects\\NIS2020\\spbk.key"));
        PublicKey publicKey = RSAEncryption.decodePublicKey(fileContent);
        fileContent = Files.readAllBytes(Paths.get("C:\\Users\\trist\\IdeaProjects\\NIS2020\\sprk.key"));
        PrivateKey privateKey = RSAEncryption.decodePrivateKey(fileContent);

        String message = "This is the secret test message";

        //Encryption
        byte[] encryptedMessage = RSAEncryption.encrypt(message.getBytes(), publicKey);

        //Decryption
        byte[] decryptedMessage = RSAEncryption.decrypt(encryptedMessage, privateKey);

        System.out.println("Original Message -> " + message);
        System.out.print("Encrypted Message -> "); System.out.println(new String(encryptedMessage));
        System.out.print("Decrypted Message -> "); System.out.println(new String(decryptedMessage));

        assertEquals(message, new String(decryptedMessage));
    }

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
        {}

        //Try decrypt with public key
        try
        {
            byte[] wrongKeyDecryptedMessage = RSAEncryption.decrypt(encryptedMessage, key.getPublic());
            assertNotEquals(message, wrongKeyDecryptedMessage);
        }
        catch (BadPaddingException ex)
        {}
    }

    /* RSA Encryption Test output

            Original Message -> This is the secret test message
            Encrypted Message -> �EUG�%(r���*��$�Īj4��m�s�lY�g�v�=�b*��:� ����)�{���*R�wm�F�uI,�W��_f��1�Ȯ.�ca������z�֚r/��-�R*`p���GI�
                                 M�C#
            Decrypted Message -> This is the secret test message
     */

    @Test
    public void encryptPrivate() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException
    {
        String message = "This is the secret test message";

        KeyPair key = RSAEncryption.generateKeyPair();

        //Encryption
        byte[] encryptedMessage = RSAEncryption.encrypt(message.getBytes(), key.getPrivate());

        //Decryption
        byte[] decryptedMessage = RSAEncryption.decrypt(encryptedMessage, key.getPublic());

        System.out.println("Original Message -> " + message);
        System.out.print("Encrypted Message -> "); System.out.println(new String(encryptedMessage));
        System.out.print("Decrypted Message -> "); System.out.println(new String(decryptedMessage));

        assertEquals(message, new String(decryptedMessage));

        //Try decrypt with different key
        KeyPair differentKey = RSAEncryption.generateKeyPair();
        try
        {
            byte[] wrongKeyDecryptedMessage = RSAEncryption.decrypt(encryptedMessage, differentKey.getPublic());
            assertNotEquals(message, wrongKeyDecryptedMessage);
        }
        catch (BadPaddingException ex)
        {}

        //Try decrypt with private key
        try
        {
            byte[] wrongKeyDecryptedMessage = RSAEncryption.decrypt(encryptedMessage, key.getPrivate());
            assertNotEquals(message, wrongKeyDecryptedMessage);
        }
        catch (BadPaddingException ex)
        {}

    }
}
