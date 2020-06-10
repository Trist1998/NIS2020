package messaging;

import security.RSAEncryption;

import java.io.*;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class GenCertificates
{
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException
    {
        KeyPair key = RSAEncryption.generateKeyPair();
        System.out.println(key.getPublic().getFormat());
        System.out.println(key.getPrivate().getFormat());
        FileOutputStream writer = new FileOutputStream("sprk.key");
        writer.write(key.getPrivate().getEncoded());
        writer.close();
        writer = new FileOutputStream("spbk.key");
        writer.write(key.getPublic().getEncoded());
        writer.close();
    }
}
