package security;

import org.junit.Test;

import static org.junit.Assert.*;

public class CompressionTest
{
    @Test
    public void compress()
    {
        String message = "This is the long test message. This is the long test message. This is the long test message. This is the long test message. This is the long test message";

        byte[] compressed = Compression.compress(message.getBytes());
        byte[] decompressed = Compression.decompress(compressed);

        System.out.println("Message - " + message);
        System.out.print("Compressed message - "); System.out.println(new String(compressed));
        System.out.print("Decompressed - ");System.out.println(new String(decompressed));

        assertEquals(message, new String(decompressed));
    }
}
