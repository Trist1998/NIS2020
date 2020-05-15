package messaging;

import security.PGPMessageManager;

import java.net.Socket;

public class Client
{

    private static final String HOST_NAME = "localhost";

    public static void main(String[] args)
    {
        openSocketClient(Server.SERVER_PORT);
    }

    public static void openSocketClient(int portNumber)
    {
        try
        {
            System.out.println("Waiting for connection");
            Socket myClient = new Socket(HOST_NAME, portNumber);
            System.out.println("Connection made. Performing Key Exchange...");
            PGPMessageManager manager = PGPMessageManager.getClientInstance(myClient);
            System.out.println("Key exchange successful. You can start messaging:");
            Messenger messenger = new Messenger(myClient, manager);
            messenger.run();
        }
        catch (Exception e)
        {
            System.out.println(e);
        }

    }
}
