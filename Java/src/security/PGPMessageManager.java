package security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
            //Read in the CA certificate
            byte[] fileContent = Files.readAllBytes(Paths.get("NIS_CA.cer"));
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(fileContent);
            X509Certificate CA = (X509Certificate)certFactory.generateCertificate(in);

            //Read in the server private key
            fileContent = Files.readAllBytes(Paths.get("Server.pri"));
            PrivateKey privateKey = RSAEncryption.decodePrivateKey(fileContent);

            //Obtain the client certificate from the socket stream and verify it
            in = new ByteArrayInputStream(receiveKeyBytes(socket.getInputStream()));
            X509Certificate clientCert = (X509Certificate)certFactory.generateCertificate(in);
            System.out.println("Received client certificate");
            clientCert.checkValidity();
            clientCert.verify(CA.getPublicKey());
            System.out.println("Client certificate has been verified");

            //Read in and send the server certificate to the client
            fileContent = Files.readAllBytes(Paths.get("Server.cer"));
            certFactory = CertificateFactory.getInstance("X.509");
            in = new ByteArrayInputStream(fileContent);
            X509Certificate serverCert = (X509Certificate)certFactory.generateCertificate(in);
            sendCertificate(serverCert, socket.getOutputStream());

            System.out.println("\nServer Private Key: ");
            System.out.println(clientCert.getPublicKey().getEncoded());
            System.out.println("\nClient Public Key: ");
            System.out.println(clientCert.getPublicKey().getEncoded());


            return new PGPMessageManager(clientCert.getPublicKey(), privateKey);
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
            //Read in and send the client certificate to the server
            byte[] fileContent = Files.readAllBytes(Paths.get("Client.cer"));
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(fileContent);
            X509Certificate clientCert = (X509Certificate)certFactory.generateCertificate(in);
            sendCertificate(clientCert, socket.getOutputStream());

            //Read in the CA certificate
            fileContent = Files.readAllBytes(Paths.get("NIS_CA.cer"));
            certFactory = CertificateFactory.getInstance("X.509");
            in = new ByteArrayInputStream(fileContent);
            X509Certificate CA = (X509Certificate)certFactory.generateCertificate(in);

            //Read in the client private key
            fileContent = Files.readAllBytes(Paths.get("Client.pri"));
            PrivateKey privateKey = RSAEncryption.decodePrivateKey(fileContent);

            //Obtain the server certificate from the socket stream and verify it
            in = new ByteArrayInputStream(receiveKeyBytes(socket.getInputStream()));
            X509Certificate serverCert = (X509Certificate)certFactory.generateCertificate(in);
            System.out.println("Received server certificate");
            serverCert.checkValidity();
            serverCert.verify(CA.getPublicKey());
            System.out.println("Server certificate has been verified");

            return new PGPMessageManager(serverCert.getPublicKey(), privateKey);
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
        byte[] sessionKeyArray = sessionKey.getEncoded();
        byte[] encryptedSessionKey = RSAEncryption.encrypt(sessionKeyArray, publicKey);

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

    private static void sendCertificate(X509Certificate certificate, OutputStream outputStream) throws IOException, CertificateEncodingException {
        outputStream.write(certificate.getEncoded());
        outputStream.flush();
    }

    private static byte[] receiveKeyBytes(InputStream reader) throws IOException
    {
        byte[] data = new byte[2048];
        int nRead = reader.read(data, 0, data.length);
        return Arrays.copyOfRange(data, 0, nRead);
    }
}
