import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import java.util.Base64;
import java.util.HashMap;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class P2Server {
    private static final int PORT = 2222;
    private static List<PrintWriter> clientWriters = new ArrayList<>();
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static Map<String, String> userCredentials = new HashMap<>();

    /**
     * Main Running of the server
     * @param args
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {

        // Initialize user credentials (username, password)
        //This would normally be from a db
        userCredentials.put("username1", "password3202@");
        userCredentials.put("username2", "password3202@@");

        //Try create a new server socket with the given port
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {

            System.out.println("Chat server is running on port " + PORT);

            // Generate a key pair for public key encryption
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
            //Run the server
            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                new ClientHandler(socket).run();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static class ClientHandler extends Thread {
        private SSLSocket socket;
        private PrintWriter out;
        private BufferedReader in;

        public ClientHandler(SSLSocket socket) {
            this.socket = socket;
        }

        /**
         * Method for handling client messages
         */
        public void run() {
            try {

                //Initialise the output stream 
                out = new PrintWriter(socket.getOutputStream(), true);
                synchronized (clientWriters) {
                    clientWriters.add(out);
                }

                //Get the inputs from the clients
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String message;

                //The first two lines should be the username and password
                String username = in.readLine();
                String encryptedPassword = in.readLine();
                String decryptedPassword = decryptPassword(encryptedPassword);

                if (authenticateUser(username, decryptedPassword)) {
                    System.out.println("User '" + username + "' authenticated.");


                    synchronized (clientWriters) {
                        clientWriters.add(out);
                    }

                    //Send the public key to the user
                    out.println(KeyUtils.getPublicKeyBytes(publicKey));
                    

                    //Read and broadcast the message other clients
                    while ((message = in.readLine()) != null) {
                        System.out.println("Received: " + message);
                        broadcastMessage(message);
                    }
                } else {
                    System.out.println("Authentication failed for user '" + username + "'.");
                    socket.close();
                }

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                //Finally ensure the socket is closed and the streams are all sent out and finished. 
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                synchronized (clientWriters) {
                    clientWriters.remove(out);
                }
            }
        }
    }

    /**
     * Simple method to write the message to a stream
     * @param message
     */
    private static void broadcastMessage(String message) {
        synchronized (clientWriters) {
            for (PrintWriter writer : clientWriters) {
                writer.println(message);
            }
        }
    }

    /**
     * Decrypts the passwords of users
     * @param encryptedPassword
     * @return
     * @throws Exception
    */
    private static String decryptPassword(String encryptedPassword) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decryptedBytes);
    }

    //Ensures the user password matches our records
    private static boolean authenticateUser(String username, String password) {
            String storedPassword = userCredentials.get(username);
            return storedPassword != null && storedPassword.equals(password);
    }
    
}

