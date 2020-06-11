package messaging;

import security.PGPMessageManager;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Scanner;

public class Messenger
{
    private Socket socket;
    private OutputStream writer;
    private PGPMessageManager securityManager;

    public Messenger(Socket socket, PGPMessageManager securityManager) throws IOException
    {
        this.socket = socket;
        this.writer = socket.getOutputStream();
        this.securityManager = securityManager;
    }

    public void run()
    {
        startReceiveThread();
        startSendThread();
    }

    private void startSendThread()
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

    private void sendMessage(String message)
    {
        try
        {
            byte[] payload = securityManager.generatePGPMessage(message);
            System.out.println("DEBUG PGP Message: ");
            System.out.println(new String(payload));
            byte[] length = ByteBuffer.allocate(4).putInt(payload.length).array();
            writer.write(length);
            writer.write(payload);
            writer.flush();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.out.println("Error Sending");
        }
    }

    public void receiveMessage()
    {
        while(true)
        {
            try
            {
                System.out.println("Them: "+securityManager.openPGPMessage(processInputStream()));
            }
            catch (IOException e)
            {
                System.out.println("Connection Closed");
                break;
            }
            catch (Exception e)
            {
                System.out.println("Receive message error");
            }
        }

    }

    public byte[] processInputStream() throws IOException
    {
        byte[] lengthArray = new byte[4];
        socket.getInputStream().read(lengthArray, 0, 4);
        int length = ByteBuffer.wrap(lengthArray).getInt();
        byte[] data = new byte[length];
        socket.getInputStream().read(data, 0, data.length);
        return data;
    }

    public PGPMessageManager getSecurityManager()
    {
        return securityManager;
    }
}
