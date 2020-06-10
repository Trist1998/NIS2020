package messaging;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class GenCertificates
{
    public static void createCertificates() throws Exception
    {
        //Generate the CA certificate
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair CAKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate CA = createCertificate("CN=NIS_CA", "CN=NIS_CA", CAKeyPair.getPublic(), CAKeyPair.getPrivate());
        FileOutputStream fos = new FileOutputStream("NIS_CA.cer");
        fos.write(CA.getEncoded());
        fos.close();
        fos = new FileOutputStream("NIS_CA.pri");
        fos.write(CAKeyPair.getPrivate().getEncoded());
        fos.close();

        //Generate the client certificate, which is signed by the CA
        KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate clientCert = createCertificate("CN=Client", "CN=NIS_CA", clientKeyPair.getPublic(), CAKeyPair.getPrivate(), CAKeyPair.getPublic());
        fos = new FileOutputStream("Client.cer");
        fos.write(clientCert.getEncoded());
        fos.close();
        fos = new FileOutputStream("Client.pri");
        fos.write(clientKeyPair.getPrivate().getEncoded());
        fos.close();

        //Generate the server certificate, which is signed by the CA
        KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate serverCert = createCertificate("CN=Server", "CN=NIS_CA", serverKeyPair.getPublic(), CAKeyPair.getPrivate(), CAKeyPair.getPublic());
        fos = new FileOutputStream("Server.cer");
        fos.write(serverCert.getEncoded());
        fos.close();
        fos = new FileOutputStream("Server.pri");
        fos.write(serverKeyPair.getPrivate().getEncoded());
        fos.close();
    }

    private static X509Certificate createCertificate(String domain, String issuer, PublicKey publicKey, PrivateKey privateKey) throws Exception
    {
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
        certGenerator.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGenerator.setSubjectDN(new X509Name(domain));
        certGenerator.setIssuerDN(new X509Name(issuer));
        certGenerator.setNotBefore(new Date(1577829600000l));
        certGenerator.setNotAfter(new Date(1640383200000l));
        certGenerator.setPublicKey(publicKey);
        certGenerator.setSignatureAlgorithm("SHA256WithRSAEncryption");
        return (X509Certificate) certGenerator.generate(privateKey, "BC");
    }

    private static X509Certificate createCertificate(String domain, String issuer, PublicKey publicKey, PrivateKey privateKey, PublicKey CAPublicKey) throws Exception
    {
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
        certGenerator.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGenerator.setSubjectDN(new X509Name(domain));
        certGenerator.setIssuerDN(new X509Name(issuer));
        certGenerator.setNotBefore(new Date(1577829600000l));
        certGenerator.setNotAfter(new Date(1640383200000l));
        certGenerator.setPublicKey(publicKey);
        certGenerator.setSignatureAlgorithm("SHA256WithRSAEncryption");
        certGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(CAPublicKey));
        return (X509Certificate) certGenerator.generate(privateKey, "BC");
    }

    public static void main(String[] args) throws Exception {
        /*KeyPair key = RSAEncryption.generateKeyPair();
        System.out.println(key.getPublic().getFormat());
        System.out.println(key.getPrivate().getFormat());
        FileOutputStream writer = new FileOutputStream("sprk.key");
        writer.write(key.getPrivate().getEncoded());
        writer.close();
        writer = new FileOutputStream("spbk.key");
        writer.write(key.getPublic().getEncoded());
        writer.close();*/

        Security.addProvider(new BouncyCastleProvider());
        createCertificates();
    }
}
