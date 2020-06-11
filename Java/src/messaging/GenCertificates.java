package messaging;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import security.RSAEncryption;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class GenCertificates
{
    public static void createCertificates(String root, String one, String two) throws Exception
    {
        //Generate the CA certificate
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //keyPairGenerator.initialize(2048);
        KeyPair CAKeyPair = RSAEncryption.generateKeyPair(); //keyPairGenerator.generateKeyPair();
        X509Certificate CA = createCertificate("CN="+root, "CN="+root, CAKeyPair.getPublic(), CAKeyPair.getPrivate());
        FileOutputStream fos = new FileOutputStream(root+".cer");
        fos.write(CA.getEncoded());
        fos.close();
        fos = new FileOutputStream(root+".pri");
        fos.write(CAKeyPair.getPrivate().getEncoded());
        fos.close();

        //Generate the client certificate, which is signed by the CA
        KeyPair clientKeyPair = RSAEncryption.generateKeyPair(); //keyPairGenerator.generateKeyPair();
        X509Certificate clientCert = createCertificate("CN="+one, "CN="+root, clientKeyPair.getPublic(), CAKeyPair.getPrivate(), CAKeyPair.getPublic());
        fos = new FileOutputStream(one+".cer");
        fos.write(clientCert.getEncoded());
        fos.close();
        fos = new FileOutputStream(one+".pri");
        fos.write(clientKeyPair.getPrivate().getEncoded());
        fos.close();

        //Generate the server certificate, which is signed by the CA
        KeyPair serverKeyPair = RSAEncryption.generateKeyPair(); //keyPairGenerator.generateKeyPair();
        X509Certificate serverCert = createCertificate("CN="+two, "CN="+root, serverKeyPair.getPublic(), CAKeyPair.getPrivate(), CAKeyPair.getPublic());
        fos = new FileOutputStream(two+".cer");
        fos.write(serverCert.getEncoded());
        fos.close();
        fos = new FileOutputStream(two+".pri");
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
        createCertificates("NIS_CA","Client","Server");
    }
}
