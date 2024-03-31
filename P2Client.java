import javax.crypto.Cipher;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.net.*;


public class P2Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 2222;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static String username;
    private static String password;
    

    public static void main(String[] args) throws Exception {
        // Initialize your username and password
        username = args[0];
        password = args[1];

        //try initilise a new socket
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT)) {
            System.out.println("Connected to the chat server.");

            //Setup the input and output including for the keys
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            DataInputStream serverKeyStream = new DataInputStream(socket.getInputStream());
            byte[] serverKeyBytes = new byte[serverKeyStream.readInt()];
            serverKeyStream.readFully(serverKeyBytes);
            publicKey = KeyUtils.getPublicKeyFromBytes(serverKeyBytes);

            //write out the username then the password
            DataOutputStream usernameStream = new DataOutputStream(socket.getOutputStream());
            usernameStream.writeUTF(username);
            DataOutputStream passwordStream = new DataOutputStream(socket.getOutputStream());
            passwordStream.writeUTF(encryptMessage(password, publicKey));


            new Thread(() -> {
                try {
                    //Read the input from the server and decrypt it
                    BufferedReader serverIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String serverMessage;
                    while ((serverMessage = serverIn.readLine()) != null) {
                        String decryptedMessage = decryptMessage(serverMessage);
                        System.out.println("Server: " + decryptedMessage);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            //Send the clients public key to the server
            DataOutputStream publicKeyStream = new DataOutputStream(socket.getOutputStream());
            byte[] clientKeyBytes = KeyUtils.getPublicKeyBytes(publicKey);
            publicKeyStream.writeInt(clientKeyBytes.length);
            publicKeyStream.write(clientKeyBytes);

            //Now decrypt and print out messages received
            String message;
            while ((message = in.readLine()) != null) {
                String encryptedMessage = encryptMessage(message, publicKey);
                out.println(encryptedMessage);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Simple encryption method
     * @param message
     * @param publicKey
     * @return
     * @throws Exception
     */
    private static String encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Simple decryption method
     * @param encryptedMessage
     * @return
     * @throws Exception
     */
    private static String decryptMessage(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
