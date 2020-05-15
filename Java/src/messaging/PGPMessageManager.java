package messaging;

import security.AESEncryption;
import security.Hashing;
import security.RSAEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CommandAPDU;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PGPMessageManager
{
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private PGPMessageManager(PublicKey publicKey, PrivateKey privateKey)
    {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] generatePGPMessage(String message) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException
    {
        //Generate session key
        Key sessionKey = AESEncryption.generateKey();

        byte[] compressedMessage = Compression.compress(message.getBytes());//TODO Compress message
        byte[] encryptedMessage = AESEncryption.encrypt(compressedMessage, sessionKey);

        byte[] messageDigest = Hashing.getDigest(message);



        return new byte[11];

    }

    public String openPGPMessage(byte[] pgpPayload)
    {

        return "Secret Message";
    }


    public static PGPMessageManager getServerInstance(Socket socket)
    {
        try
        {
            KeyPair pair = RSAEncryption.generateKeyPair();

            //This key exchange should be done with Certificate Authority
            sendPublicKey(pair.getPublic(), socket.getOutputStream());
            PublicKey receivedPublicKey = receivePublicKey(socket.getInputStream());

            return new PGPMessageManager(receivedPublicKey, pair.getPrivate());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return null;
    }

    public static PGPMessageManager getClientInstance(Socket socket)
    {
        try
        {
            KeyPair pair = RSAEncryption.generateKeyPair();

            //This key exchange should be done with Certificate Authority
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

    private byte[] encryptMessage(String message, Key key) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException
    {
        return AESEncryption.encrypt(message, key);
    }

    private String decryptMessage(String message, Key key) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException
    {
        return AESEncryption.decrypt(message.getBytes(), key);
    }

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
