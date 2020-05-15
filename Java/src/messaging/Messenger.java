package messaging;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Messenger
{
    private static String MESSAGE_END = "MESSAGE_END";
    private Socket socket;
    private BufferedReader reader;
    private OutputStream writer;
    private PGPMessageManager securityManager;

    public Messenger(Socket socket, PGPMessageManager securityManager) throws IOException
    {
        this.socket = socket;
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        writer = socket.getOutputStream();
        this.securityManager = securityManager;
    }

    public void run() throws IOException
    {
        startReceiveThread();
        startSendThread();
    }

    private void startSendThread() throws IOException
    {
        boolean loop = true;
        while(loop)
        {
            Scanner input = new Scanner(System.in);
            String message = input.nextLine();
            if(message.equals("!exit"))
                break;
            try
            {
                sendMessage(message);
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }

    private void startReceiveThread()
    {
        new Thread(() -> {
            try
            {
                receiveMessage();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }).start();
    }

    private void sendMessage(String message) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException
    {
        writer.write(securityManager.generatePGPMessage(message));
        writer.flush();
    }

    private void receiveMessage() throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException
    {
        String message = "";
        for(;;)
        {
            String line = null;
            try
            {
                line = reader.readLine();
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }

            if(line.trim().equals(MESSAGE_END))
            {
                //System.out.println("Message: " + message.replaceAll("MESSAGE__", "MESSAGE_"));
                System.out.println(securityManager.openPGPMessage(message.getBytes()).replaceAll("MESSAGE__", "MESSAGE_"));
                message = "";
            }
            else
                message += line;
        }


    }
}
