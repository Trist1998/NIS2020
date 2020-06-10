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

        assertTrue(compressed.length < decompressed.length);
        assertEquals(message, new String(decompressed));
    }

    /* Test Output:
            Message - This is the long test message. This is the long test message. This is the long test message. This is the long test message. This is the long test message
            Compressed message - x���,V ���T����t�����������T=��� U16�
            Decompressed - This is the long test message. This is the long test message. This is the long test message. This is the long test message. This is the long test message
     */
}
