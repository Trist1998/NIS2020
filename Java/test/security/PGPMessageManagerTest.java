package security;


import org.junit.Test;
import security.PGPMessageManager;
import security.RSAEncryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.*;

public class PGPMessageManagerTest
{

    @Test
    public void pgpMessageTest() throws Exception
    {
        KeyPair personAKey = RSAEncryption.generateKeyPair();
        KeyPair personBKey = RSAEncryption.generateKeyPair();

        PGPMessageManager personAManager = new PGPMessageManager(personBKey.getPublic(), personAKey.getPrivate());
        PGPMessageManager personBManager = new PGPMessageManager(personAKey.getPublic(), personBKey.getPrivate());

        String message = "This is the secret test message";
        byte[] payload = personAManager.generatePGPMessage(message);
        //Confirms message is encrypted
        assertFalse(new String(payload).contains(message));

        String decryptedMessage = personBManager.openPGPMessage(payload);

        System.out.println("Original Message -> " + message);
        System.out.println("Encrypted Message Payload: "); System.out.println(new String(payload));
        System.out.println("Decrypted Message -> " + decryptedMessage);

        //Confirms the message can be decrypted
        assertEquals(decryptedMessage, message);
    }

    /* Example output:

            Original Message -> This is the secret test message
            Encrypted Message Payload:
            ��r���w��P�6������vh��`�_�;�32轶�q0�$��;����e��	��)y��
            ����|��SK�`��7|׬��E�C�F����8�~�d��MܯM9+o�̅+Go��4�t�K�oa�q���~�|�.�����c�XG���k�"^8��-�5��O?j
            ��3�W7
            ncQ
            �n�F9c�^���z���%۵
            T{DI
            o=�j��l	(�_Z��E�U3Ve*+/�ٜ��G�
            Decrypted Message -> This is the secret test message

     */
}
