package messaging;


import org.junit.Test;
import security.RSAEncryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.*;

public class PGPMessageManagerTest
{

    @Test
    public void generatePGPMessage() throws Exception
    {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance(RSAEncryption.ALGORITHM_STRING);
        KeyPair personAKey = pairGenerator.generateKeyPair();
        KeyPair personBKey = pairGenerator.generateKeyPair();

        PGPMessageManager personAManager = new PGPMessageManager(personBKey.getPublic(), personAKey.getPrivate());
        PGPMessageManager personBManager = new PGPMessageManager(personAKey.getPublic(), personBKey.getPrivate());

        String message = "This is the secret test message";
        byte[] payload = personAManager.generatePGPMessage(message);

        String decryptedMessage = personBManager.openPGPMessage(payload);
        assertEquals(decryptedMessage, message);
    }

    @Test
    public void openPGPMessage()
    {
    }
}
