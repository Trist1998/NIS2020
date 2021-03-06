package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Hashing
{

    public static byte[] getDigest(String message) throws NoSuchAlgorithmException
    {
        return getDigest(message.getBytes());
    }

    public static byte[] getDigest(byte[] messageBytes) throws NoSuchAlgorithmException
    {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] output = messageDigest.digest(messageBytes);
        return output;
    }


    public static boolean authenticateMessage(String message, byte[] digest)
    {
        return authenticateMessage(message.getBytes(), digest);
    }

    public static boolean authenticateMessage(byte[] message, byte[] digest)
    {
        try
        {
            byte[] newDigest = getDigest(message);
            return Arrays.equals(newDigest, digest);
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        return false;
    }
}
