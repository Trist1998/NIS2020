package messaging;

import java.io.*;
import java.net.Socket;
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
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.writer = socket.getOutputStream();
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

    private void sendMessage(String message) throws IOException, NoSuchAlgorithmException
    {
        writer.write(securityManager.generatePGPMessage(message));
        writer.flush();
    }

    private void receiveMessage()
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
                System.out.println(securityManager.openPGPMessage(message.getBytes()));
                message = "";
            }
            else
                message += line;
        }


    }
}
