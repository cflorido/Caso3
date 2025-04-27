import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;

public class ClienteDelegado extends Thread {
    private String ipServidor;
    private int puertoServidor;
    private static final String PUBLIC_KEY_FILE = "servidor_public.key";

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
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey K_w_plus = keyFactory.generatePublic(publicSpec);

            // 1. Enviar "HELLO"
            out.writeUTF("HELLO");

            // 2. Generar y enviar reto
            SecureRandom random = new SecureRandom();
            byte[] reto = new byte[32];
            random.nextBytes(reto);
            out.writeInt(reto.length);
            out.write(reto);

            // 4. Esperar respuesta y verificar
            int rtaLength = in.readInt();
            byte[] rta = new byte[rtaLength];
            in.readFully(rta);

            // SIMETRICO O ASIMETRICO

            boolean usarCifradoAsimetrico = false; // true: RSA, false: AES

            byte[] respuestaReto;
            if (usarCifradoAsimetrico) {
                // ----- CIFRADO ASIMÉTRICO (RSA) -----
                Cipher rsaCipher = Cipher.getInstance("RSA");
                rsaCipher.init(Cipher.DECRYPT_MODE, K_w_plus);
                respuestaReto = rsaCipher.doFinal(rta);
            } else {
                // ----- CIFRADO SIMÉTRICO (AES) -----
                Cipher aesCipherSim = Cipher.getInstance("AES/ECB/PKCS5Padding");
                SecretKey keySimetricaTemporal = new SecretKeySpec("1234567890123456".getBytes(), "AES");
                aesCipherSim.init(Cipher.DECRYPT_MODE, keySimetricaTemporal);
                respuestaReto = aesCipherSim.doFinal(rta);
            }

            if (Arrays.equals(reto, respuestaReto)) {
                out.writeUTF("OK");
            } else {
                out.writeUTF("ERROR");
                socket.close();
                return;
            }

            // 8. Recibir G, P, G^x
            int gLength = in.readInt();
            byte[] G = new byte[gLength];
            in.readFully(G);

            int pLength = in.readInt();
            byte[] P = new byte[pLength];
            in.readFully(P);

            int gxLength = in.readInt();
            byte[] Gx = new byte[gxLength];
            in.readFully(Gx);

            // 9. Recibir firma y verificar
            int firmaLength = in.readInt();
            byte[] firmaBytes = new byte[firmaLength];
            in.readFully(firmaBytes);

            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initVerify(K_w_plus);
            firma.update(G);
            firma.update(P);
            firma.update(Gx);

            if (firma.verify(firmaBytes)) {
                out.writeUTF("OK");
            } else {
                out.writeUTF("ERROR");
                socket.close();
                return;
            }

            // 11. Generar par de llaves DH
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Gx);
            PublicKey pubServerKey = kf.generatePublic(x509KeySpec);
            DHParameterSpec dhSpec = ((DHPublicKey) pubServerKey).getParams();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair dhKeyPair = kpg.generateKeyPair();
            PrivateKey privDH = dhKeyPair.getPrivate();
            PublicKey pubDH = dhKeyPair.getPublic();

            byte[] Gy = pubDH.getEncoded();
            out.writeInt(Gy.length);
            out.write(Gy);

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privDH);
            ka.doPhase(pubServerKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derivar K_AB1 y K_AB2
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] fullKey = sha512.digest(sharedSecret);
            SecretKey K_AB1 = new SecretKeySpec(Arrays.copyOfRange(fullKey, 0, 32), "AES");
            SecretKey K_AB2 = new SecretKeySpec(Arrays.copyOfRange(fullKey, 32, 64), "HmacSHA256");

            // 12. Generar IV y enviarlo
            SecureRandom ivRandom = new SecureRandom();
            byte[] ivBytes = new byte[16];
            ivRandom.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            out.writeInt(ivBytes.length);
            out.write(ivBytes);

            // 13. Recibir tabla cifrada y HMAC
            int tablaLength = in.readInt();
            byte[] tablaCifrada = new byte[tablaLength];
            in.readFully(tablaCifrada);

            int hmacLength = in.readInt();
            byte[] hmacTabla = new byte[hmacLength];
            in.readFully(hmacTabla);

            // Verificar HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(K_AB2);
            byte[] hmacCheck = hmac.doFinal(tablaCifrada);

            if (!Arrays.equals(hmacTabla, hmacCheck)) {
                socket.close();
                return;
            }

            // 14. Cifrar id_servicio + IP_cliente y mandar HMAC
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);

            // Elegir aleatoriamente el servicio
            String[] servicios = { "S1", "S2", "S3" };
            String ipCliente = "192.168.1.100";
            Random randomser = new Random();
            int indiceAleatorio = randomser.nextInt(servicios.length);
            String servicioElegido = servicios[indiceAleatorio];

            String peticion = servicioElegido + "," + ipCliente;

            // Cifrar la petición

            // (cifrado simétrico AES)
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
            byte[] peticionCifrada = aesCipher.doFinal(peticion.getBytes());

            // Enviar petición cifrada
            out.writeInt(peticionCifrada.length);
            out.write(peticionCifrada);

            // Hacer y enviar el HMAC de la petición
            hmac.init(K_AB2);
            byte[] hmacPeticion = hmac.doFinal(peticionCifrada);
            out.writeInt(hmacPeticion.length);
            out.write(hmacPeticion);

            // Recibir la respuesta cifrada
            int respLength = in.readInt();
            byte[] respCifrada = new byte[respLength];
            in.readFully(respCifrada);

            // Recibir HMAC de la respuesta
            int hmacRespLength = in.readInt();
            byte[] hmacResp = new byte[hmacRespLength];
            in.readFully(hmacResp);

            // Verificar HMAC de la respuesta
            hmac.init(K_AB2);
            byte[] hmacRespCheck = hmac.doFinal(respCifrada);
            if (!Arrays.equals(hmacResp, hmacRespCheck)) {
                System.out.println("HMAC de respuesta no válido en consulta ");

            }

            // Descifrar la respuesta
            aesCipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
            byte[] respuestaFinal = aesCipher.doFinal(respCifrada);
            String ipServidor = new String(respuestaFinal);

            System.out.println("Consulta: IP y puerto del servicio: " + ipServidor);

            // Enviar "OK"
            out.writeUTF("OK");

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
