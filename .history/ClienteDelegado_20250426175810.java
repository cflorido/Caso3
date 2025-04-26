import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.*;

public class ClienteDelegado extends Thread {
    private String ipServidor;
    private int puertoServidor;

    public ClienteDelegado(String ipServidor, int puertoServidor) {
        this.ipServidor = ipServidor;
        this.puertoServidor = puertoServidor;
    }

    @Override
    public void run() {
        try {
            Socket socket = new Socket(ipServidor, puertoServidor);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Leer llaves del cliente
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get("servidor_public.key"));
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey K_c_plus = keyFactory.generatePublic(publicSpec);

            byte[] privateKeyBytes = Files.readAllBytes(Paths.get("servidor_private.key"));
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey K_c_minus = keyFactory.generatePrivate(privateSpec);

            // 1. Enviar "HELLO"
            out.writeUTF("HELLO");

            // 2. Enviar un reto
            SecureRandom random = new SecureRandom();
            byte[] reto = new byte[32];
            random.nextBytes(reto);

            out.writeInt(reto.length);
            out.write(reto);

            // 4. Recibir respuesta cifrada
            int rtaLength = in.readInt();
            byte[] rta = new byte[rtaLength];
            in.readFully(rta);

            // Verificar respuesta
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, K_c_plus);
            byte[] retoRecibido = rsaCipher.doFinal(rta);

            if (Arrays.equals(reto, retoRecibido)) {
                out.writeUTF("OK");
            } else {
                out.writeUTF("ERROR");
                socket.close();
                return;
            }

            // 7. Recibir G, P, G^x
            int gLength = in.readInt();
            byte[] G = new byte[gLength];
            in.readFully(G);

            int pLength = in.readInt();
            byte[] P = new byte[pLength];
            in.readFully(P);

            int gxLength = in.readInt();
            byte[] Gx = new byte[gxLength];
            in.readFully(Gx);

            // Recibir firma
            int firmaLength = in.readInt();
            byte[] firmaBytes = new byte[firmaLength];
            in.readFully(firmaBytes);

            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initVerify(K_c_plus);
            firma.update(G);
            firma.update(P);
            firma.update(Gx);
            boolean verificada = firma.verify(firmaBytes);

            if (verificada) {
                out.writeUTF("OK");
            } else {
                out.writeUTF("ERROR");
                socket.close();
                return;
            }

            // Generar G^y
            KeyFactory kf = KeyFactory.getInstance("DH");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhSpec = new DHParameterSpec(new java.math.BigInteger(P), new java.math.BigInteger(G));
            kpg.initialize(dhSpec);
            KeyPair kp = kpg.generateKeyPair();
            PrivateKey privKey = kp.getPrivate();
            PublicKey pubKey = kp.getPublic();

            byte[] Gy = pubKey.getEncoded();

            // 11. Enviar G^y
            out.writeInt(Gy.length);
            out.write(Gy);

            // Calcular secreto compartido
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Gx);
            PublicKey serverPubKey = kf.generatePublic(x509KeySpec);

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privKey);
            ka.doPhase(serverPubKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derivar K_AB1 y K_AB2
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] fullKey = sha512.digest(sharedSecret);
            SecretKey K_AB1 = new SecretKeySpec(Arrays.copyOfRange(fullKey, 0, 32), "AES");
            SecretKey K_AB2 = new SecretKeySpec(Arrays.copyOfRange(fullKey, 32, 64), "HmacSHA256");

            // 12b. Enviar IV
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecureRandom ivRandom = new SecureRandom();
            byte[] ivBytes = new byte[16];
            ivRandom.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            out.writeInt(ivBytes.length);
            out.write(ivBytes);

            // 13. Enviar id_servicio + IP_cliente cifrado + HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
            String[] servicios = { "S1", "S2", "S3" };
            String ipCliente = "192.168.1.100";
            Random randomser = new Random();
            int indiceAleatorio = randomser.nextInt(servicios.length);
            String servicioElegido = servicios[indiceAleatorio];

            String solicitud = servicioElegido + "," + ipCliente;

            byte[] solicitudCifrada = aesCipher.doFinal(solicitud.getBytes());

            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(K_AB2);
            byte[] hmacSolicitud = hmac.doFinal(solicitudCifrada);

            out.writeInt(solicitudCifrada.length);
            out.write(solicitudCifrada);
            out.writeInt(hmacSolicitud.length);
            out.write(hmacSolicitud);

            // 16. Recibir IP servidor y puerto cifrados + HMAC
            int respuestaLength = in.readInt();
            byte[] respuestaCifrada = new byte[respuestaLength];
            in.readFully(respuestaCifrada);

            int hmacRespuestaLength = in.readInt();
            byte[] hmacRespuesta = new byte[hmacRespuestaLength];
            in.readFully(hmacRespuesta);

            byte[] hmacCheck = hmac.doFinal(respuestaCifrada);
            if (!Arrays.equals(hmacRespuesta, hmacCheck)) {
                socket.close();
                return;
            }

            aesCipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
            byte[] respuesta = aesCipher.doFinal(respuestaCifrada);

            System.out.println("ClienteDelegado recibió respuesta: " + new String(respuesta));

            out.writeUTF("OK");

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
