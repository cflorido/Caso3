import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServidorDelegado extends Thread {
    private Socket socket;

    public ServidorDelegado(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // 0a. Leer llaves del archivo
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get("servidor_public.key"));
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey K_w_plus = keyFactory.generatePublic(publicSpec);

            // Leer llave privada
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get("servidor_private.key"));
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey K_w_minus = keyFactory.generatePrivate(privateSpec);

            // 1. Esperar "HELLO"
            String hello = in.readUTF();
            if (!hello.equals("HELLO")) {
                socket.close();
                return;
            }

            // 2b. Esperar el reto que envía el cliente
            int retoLength = in.readInt();
            byte[] reto = new byte[retoLength];
            in.readFully(reto);

            // 3. Calcula Rta = C(K_w-, Reto)
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, K_w_minus);
            byte[] rta = rsaCipher.doFinal(reto);

            // 4. Enviar Rta
            out.writeInt(rta.length);
            out.write(rta);

            // 6. Esperar "OK" o "ERROR"
            String respuesta = in.readUTF();
            if (!respuesta.equals("OK")) {
                socket.close();
                return;
            }

            // 7. Genera G, P, G^x
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(512);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair dhKeyPair = kpg.generateKeyPair();
            PrivateKey privDH = dhKeyPair.getPrivate();
            PublicKey pubDH = dhKeyPair.getPublic();

            byte[] G = dhSpec.getG().toByteArray();
            byte[] P = dhSpec.getP().toByteArray();
            byte[] Gx = pubDH.getEncoded();

            // 8. Enviar G, P, G^x
            out.writeInt(G.length);
            out.write(G);
            out.writeInt(P.length);
            out.write(P);
            out.writeInt(Gx.length);
            out.write(Gx);
            long inicioFirma = System.nanoTime();
            // Firmar (G,P,G^x)
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initSign(K_w_minus);
            firma.update(G);
            firma.update(P);
            firma.update(Gx);
            byte[] firmaBytes = firma.sign();
            long finFirma = System.nanoTime();
            long tiempoFirma = finFirma - inicioFirma;
            System.out.println("Tiempo para firmar: " + tiempoFirma + " ns");

            // Enviar firma
            out.writeInt(firmaBytes.length);
            out.write(firmaBytes);

            // 10. Esperar "OK" o "ERROR"
            String verifFirma = in.readUTF();
            if (!verifFirma.equals("OK")) {
                socket.close();
                return;
            }

            // 11. Recibir G^y
            int GyLength = in.readInt();
            byte[] Gy = new byte[GyLength];
            in.readFully(Gy);

            // Calcular (G^y)^x
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Gy);
            PublicKey pubClientKey = kf.generatePublic(x509KeySpec);

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privDH);
            ka.doPhase(pubClientKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derivar K_AB1 y K_AB2
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] fullKey = sha512.digest(sharedSecret);
            SecretKey K_AB1 = new SecretKeySpec(Arrays.copyOfRange(fullKey, 0, 32), "AES");
            SecretKey K_AB2 = new SecretKeySpec(Arrays.copyOfRange(fullKey, 32, 64), "HmacSHA256");

            // 12b. Recibir IV
            int ivLength = in.readInt();
            byte[] ivBytes = new byte[ivLength];
            in.readFully(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // 13. Cifrar tabla de servicios y mandar HMAC
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);

            String tablaServicios = "IdServicio Servicio IP Puerto\n" +
                    "S1 Estado_vuelo IPS1 PS1\n" +
                    "S2 Disponibilidad_vuelos IPS2 PS2\n" +
                    "S3 Costo_de_un_vuelo IPS3 PS3";

            long inicioCifradoTabla = System.nanoTime();
            byte[] tablaCifrada = aesCipher.doFinal(tablaServicios.getBytes());
            long finCifradoTabla = System.nanoTime();
            long tiempoCifradoTabla = finCifradoTabla - inicioCifradoTabla;
            System.out.println("Tiempo para cifrar la tabla: " + tiempoCifradoTabla + " ns");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(K_AB2);
            byte[] hmacTabla = hmac.doFinal(tablaCifrada);

            out.writeInt(tablaCifrada.length);
            out.write(tablaCifrada);
            out.writeInt(hmacTabla.length);
            out.write(hmacTabla);

            // 14. Recibir id_servicio + IP_cliente cifrados + HMAC
            int servicioCifLength = in.readInt();
            byte[] servicioCifrado = new byte[servicioCifLength];
            in.readFully(servicioCifrado);

            int hmacServicioLength = in.readInt();
            byte[] hmacServicio = new byte[hmacServicioLength];
            in.readFully(hmacServicio);

            // Verificar HMAC
            long inicioVerificacion = System.nanoTime();
            byte[] hmacCheck = hmac.doFinal(servicioCifrado);
            long finVerificacion = System.nanoTime();
            long tiempoVerificacion = finVerificacion - inicioVerificacion;
            System.out.println("Tiempo para verificar consulta: " + tiempoVerificacion + " ns");

            if (!Arrays.equals(hmacServicio, hmacCheck)) {
                socket.close();
                return;
            }

            aesCipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
            byte[] servicioYCliente = aesCipher.doFinal(servicioCifrado);
            String recibido = new String(servicioYCliente);
            System.out.println("Peticion recibida: " + recibido);
            String[] partes = recibido.split(",");
            String idServicio = partes[0];

            String ipServidor;
            switch (idServicio) {
                case "S1":
                    ipServidor = "192.168.1.1:8001"; // IP y puerto para S1
                    break;
                case "S2":
                    ipServidor = "192.168.1.2:8002"; // IP y puerto para S2
                    break;
                case "S3":
                    ipServidor = "192.168.1.3:8003"; // IP y puerto para S3
                    break;
                default:
                    ipServidor = "-1,-1"; // Servicio no encontrado
                    break;
            }
            // 16. Cifrar IP servidor + puerto servidor y mandar HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);

            byte[] respuestaCifrada = aesCipher.doFinal(ipServidor.getBytes());

            byte[] hmacRespuesta = hmac.doFinal(respuestaCifrada);

            out.writeInt(respuestaCifrada.length);
            out.write(respuestaCifrada);
            out.writeInt(hmacRespuesta.length);
            out.write(hmacRespuesta);

            // 18. Esperar "OK"
            String finalRespuesta = in.readUTF();
            System.out.println("Servidor: Se recibio " + finalRespuesta);

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
