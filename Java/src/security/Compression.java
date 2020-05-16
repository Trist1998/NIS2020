package security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class Compression
{
    //Adapted From: https://www.java-tips.org/java-se-tips-100019/38-java-util-zip/1718-how-to-compress-a-byte-array.html
    public static byte[] compress(byte[] input)
    {
        //Setup Compressor
        Deflater compressor = new Deflater();
        compressor.setLevel(Deflater.BEST_COMPRESSION);

        //Compress the data
        compressor.setInput(input);
        compressor.finish();

        //Create an expandable byte array to hold the compressed data.
        ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length);

        //Compress the data
        byte[] buf = new byte[1024];
        while (!compressor.finished())
        {
            int count = compressor.deflate(buf);
            bos.write(buf, 0, count);
        }
        try
        {
            bos.close();
        }
        catch (IOException e)
        {
        }

        //Return the compressed data
        return bos.toByteArray();
    }

    //Adapted from: https://www.java-tips.org/java-se-tips-100019/38-java-util-zip/1719-how-to-decompress-a-byte-array.html
    public static byte[] decompress(byte[] compressedData)
    {
        //Setup the decompressor
        Inflater decompressor = new Inflater();

        //Decompress the data
        decompressor.setInput(compressedData);

        // Create an expandable byte array to hold the decompressed data
        ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);

        // Decompress the data
        byte[] buf = new byte[1024];
        while (!decompressor.finished())
        {
            try
            {
                int count = decompressor.inflate(buf);
                bos.write(buf, 0, count);
            }
            catch (DataFormatException e)
            {}
        }
        try
        {
            bos.close();
        }
        catch (IOException e)
        {}
        return bos.toByteArray();
    }
}
