package security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class PGPMessageManager
{
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public PGPMessageManager(PublicKey publicKey, PrivateKey privateKey)
    {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * Sets up PGPMessageManager for the server
     * @param socket
     * @return
     */
    public static PGPMessageManager getServerInstance(Socket socket)
    {
        try
        {
            KeyPair pair = RSAEncryption.generateKeyPair();

            System.out.println("Exchanging Keys");
            //This key exchange should be done with Certificate Authority but is like this for testing purposes
            sendPublicKey(pair.getPublic(), socket.getOutputStream());
            PublicKey receivedPublicKey = receivePublicKey(socket.getInputStream());
            System.out.println("Key exchange successful");
            return new PGPMessageManager(receivedPublicKey, pair.getPrivate());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Sets up PGPMessageManager for the client
     * @param socket
     * @return
     */
    public static PGPMessageManager getClientInstance(Socket socket)
    {
        try
        {
            KeyPair pair = RSAEncryption.generateKeyPair();

            //This key exchange should be done with Certificate Authority but is like this for testing purposes
            PublicKey receivedPublicKey = receivePublicKey(socket.getInputStream());
            sendPublicKey(pair.getPublic(), socket.getOutputStream());

            return new PGPMessageManager(receivedPublicKey, pair.getPrivate());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Generates PGP messages to be sent
     * @param message
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     */
    public byte[] generatePGPMessage(String message) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException
    {
        //Generate session key
        Key sessionKey = AESEncryption.generateKey();

        //Generate and encrypt Message Digest
        byte[] messageDigest = Hashing.getDigest(message);
        byte[] encryptedMessageDigest = RSAEncryption.encrypt(messageDigest, privateKey);

        //Combine message body
        byte[] concat = concat(encryptedMessageDigest, message.getBytes());

        //Compress and Encrypt Message Body
        byte[] compressedMessage = Compression.compress(concat);
        byte[] encryptedMessage = AESEncryption.encrypt(compressedMessage, sessionKey);

        //Encrypt the Session Key
        byte[] encryptedSessionKey = RSAEncryption.encrypt(sessionKey.getEncoded(), publicKey);

        //Combine encrypted Session Key and Compressed Message Body to create PGP Payload
        return concat(encryptedSessionKey, encryptedMessage);

    }

    /**
     * Decrypts and authenticates received PGP messages
     * @param pgpPayload
     * @return
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public String openPGPMessage(byte[] pgpPayload) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        //Split encrypted Session Key and Compressed Message Body
        byte[] encryptedSessionKey = Arrays.copyOfRange(pgpPayload, 0, 256);
        byte[] encryptedCompressedMessage = Arrays.copyOfRange(pgpPayload, 256, pgpPayload.length);

        //Decrypt Session Key
        byte[] decryptedSessionKey = RSAEncryption.decrypt(encryptedSessionKey, privateKey);
        Key sessionKey = new SecretKeySpec(decryptedSessionKey, AESEncryption.ALGORITHM_STRING);

        //Decrypt Compressed Message Body
        byte[] compressedMessage = AESEncryption.decrypt(encryptedCompressedMessage, sessionKey);

        //Decompress message body
        byte[] concat = Compression.decompress(compressedMessage);

        //Split encrypted Message Digest and Message
        byte[] encryptedMessageDigest = Arrays.copyOfRange(concat, 0, 256);
        byte[] message = Arrays.copyOfRange(concat, 256, concat.length);

        //Compare received Message Digest and generated one
        byte[] messageDigest = RSAEncryption.decrypt(encryptedMessageDigest, publicKey);
        if (Hashing.authenticateMessage(message, messageDigest))
        {
            return new String(message);
        }

        return "Message not authentic: " + message;
    }

    private byte[] concat(byte[] first, byte[] second)
    {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    /*
     * Not sure if we will end up using these functions but ill keep them here in case
     */
    private static void sendPublicKey(PublicKey publicKey, OutputStream outputStream) throws IOException
    {
        outputStream.write(publicKey.getEncoded());
        outputStream.flush();
    }

    private static PrivateKey decodePrivateKey(InputStream inputStream) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return KeyFactory.getInstance(RSAEncryption.ALGORITHM_STRING).generatePrivate(new PKCS8EncodedKeySpec(receiveKeyBytes(inputStream)));
    }

    private static PublicKey receivePublicKey(InputStream inputStream) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return KeyFactory.getInstance(RSAEncryption.ALGORITHM_STRING).generatePublic(new X509EncodedKeySpec(receiveKeyBytes(inputStream)));
    }

    private static byte[] receiveKeyBytes(InputStream inputStream)
    {
        return new byte[1];//TODO implement this
    }
}
