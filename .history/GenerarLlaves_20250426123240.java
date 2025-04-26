import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerarLlaves {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        // Generar llaves RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // 2048 bits es seguro
        KeyPair pair = keyGen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // Guardar la llave pública
        try (FileOutputStream fos = new FileOutputStream("servidor_public.key")) {
            fos.write(publicKey.getEncoded());
        }

        // Guardar la llave privada
        try (FileOutputStream fos = new FileOutputStream("servidor_private.key")) {
            fos.write(privateKey.getEncoded());
        }

        System.out.println("Llaves generadas yei");
    }
}
