package messaging;

import security.PGPMessageManager;

import java.io.IOException;
import java.net.*;


/**
 * Server class is th executable class that listens for new connections
 *
 * @author Tristan Wood
 */
public class Server
{
    public static final int SERVER_PORT = 12123;

    private Socket socket;
    private Messenger messenger;
    private PGPMessageManager manager;

    public Server(int portNumber) throws IOException
    {
        socket = openSocketServer(portNumber);
        manager = PGPMessageManager.getServerInstance(socket);
        messenger = new Messenger(socket, manager);
    }

    public static void main(String[] args) throws IOException
    {
        Server server = new Server(SERVER_PORT);
        server.getMessenger().run();
        server.close();
    }

    /**
     * Creates server socket and tries to connect, when connection request comes
     * in create new connection handler on a new thread.
     *
     * @param portNumber
     */
    public static Socket openSocketServer(int portNumber)
    {
        try
        {
            ServerSocket myService; // Declare Server's Main socket
            myService = new ServerSocket(portNumber); // Port number must be > 1023
            System.out.println("Waiting for connection");
            Socket myServer = myService.accept();
            System.out.println("Connection made");
            return myServer;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    public Messenger getMessenger()
    {
        return messenger;
    }

    public PGPMessageManager getManager()
    {
        return manager;
    }
    public void close() throws IOException
    {
        socket.close();
    }
}
