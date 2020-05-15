package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Hashing
{
    public static byte[] getDigest(String message) throws NoSuchAlgorithmException
    {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] messageBytes = message.getBytes();
        byte[] output = messageDigest.digest(messageBytes);
        return output;
    }

    public static boolean authenticateMessage(String message, byte[] digest)
    {
        try
        {
            byte[] newDigest = getDigest(message);
            return Arrays.equals(newDigest, digest);
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();//TODO Handle correctly
        }
        return false;
    }
}
