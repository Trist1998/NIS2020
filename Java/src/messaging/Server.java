package messaging;

import java.net.*;


/**
 * Server class is th executable class that listens for new connections
 *
 * @author Tristan Wood
 */
public class Server
{
    public static final int SERVER_PORT = 9999;

    public static void main(String[] args)
    {
        openSocketServer(9999);
    }

    /**
     * Creates server socket and tries to connect, when connection request comes
     * in create new connection handler on a new thread.
     *
     * @param portNumber
     */
    public static void openSocketServer(int portNumber)
    {
        try
        {
            ServerSocket myService; // Declare Server's Main socket
            myService = new ServerSocket(portNumber); // Port number must be > 1023
            System.out.println("Waiting for connection");
            Socket myServer = myService.accept();
            System.out.println("Connection made. Performing Key Exchange...");
            PGPMessageManager manager = PGPMessageManager.getServerInstance(myServer);
            System.out.println("Key exchange successful. You can start messaging:");
            Messenger messenger = new Messenger(myServer, manager);
            myService.close();
            messenger.run();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
