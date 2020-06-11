package security;

import messaging.GenCertificates;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GenCertificatesTest
{
    @Test
    public void verify() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        GenCertificates.createCertificates("TestCA","TestClient","TestServer");

        byte[] fileContent = Files.readAllBytes(Paths.get("TestCA.cer"));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(fileContent);
        X509Certificate CA = (X509Certificate)certFactory.generateCertificate(in);

        fileContent = Files.readAllBytes(Paths.get("TestClient.cer"));
        certFactory = CertificateFactory.getInstance("X.509");
        in = new ByteArrayInputStream(fileContent);
        X509Certificate clientCert = (X509Certificate)certFactory.generateCertificate(in);

        fileContent = Files.readAllBytes(Paths.get("TestServer.cer"));
        certFactory = CertificateFactory.getInstance("X.509");
        in = new ByteArrayInputStream(fileContent);
        X509Certificate serverCert = (X509Certificate)certFactory.generateCertificate(in);

        boolean verified = false;
        try
        {
            clientCert.verify(CA.getPublicKey());
            verified = true;
            assertTrue(verified);
            System.out.println("Client certificate has been correctly verified by the CA certificate.");
        }
        catch (Exception e)
        {
            System.out.println("Client certificate has failed verification.");
            e.printStackTrace();
        }

        verified = false;
        try
        {
            serverCert.verify(CA.getPublicKey());
            verified = true;
            assertTrue(verified);
            System.out.println("Server certificate has been correctly verified by the CA certificate.");
        }
        catch (Exception e)
        {
            System.out.println("Server certificate has failed verification.");
            e.printStackTrace();
        }

        verified = false;
        try
        {
            KeyPair keyPair = RSAEncryption.generateKeyPair();
            clientCert.verify(keyPair.getPublic());
            verified = true;
            assertFalse(verified);
            System.out.println("Client certificate has falsely passed verification.");
        }
        catch (Exception e)
        {
            assertFalse(verified);
            System.out.println("Client certificate has correctly failed verification.");
        }

        verified = false;
        try
        {
            KeyPair keyPair = RSAEncryption.generateKeyPair();
            serverCert.verify(keyPair.getPublic());
            verified = true;
            assertFalse(verified);
            System.out.println("Server certificate has falsely passed verification.");
        }
        catch (Exception e)
        {
            assertFalse(verified);
            System.out.println("Server certificate has correctly failed verification.");
        }
    }
}
