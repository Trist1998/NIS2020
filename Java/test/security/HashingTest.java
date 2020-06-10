package security;

import org.junit.Test;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;

public class HashingTest
{
    @Test
    public void authenticateMessage() throws NoSuchAlgorithmException
    {
        String message = "Test message for the hashing function";

        byte[] digest = Hashing.getDigest(message);

        String correctMessage = "Test message for the hashing function";
        assertTrue(Hashing.authenticateMessage(correctMessage, digest));

        String wrongMessage = "Not the test message for the hashing function!";
        assertFalse(Hashing.authenticateMessage(wrongMessage, digest));

        String typoWrongMessage = "Test nessage for the hashing function";
        assertFalse(Hashing.authenticateMessage(typoWrongMessage, digest));

        System.out.println("Message-> " + message);
        System.out.println("Message Hash-> "+ Hashing.getDigest(message));
    }

    /* Hashing test ouput:

        Message-> Test message for the hashing function
        Message Hash-> [B@15327b79

     */
}
