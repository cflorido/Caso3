import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServidorPrincipal {
    public static void main(String[] args) throws Exception {
        ServerSocket servidor = new ServerSocket(5000);
        Socket socket = servidor.accept();
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // 0a. Leer llaves del archivo
        // Leer llave pública
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

        // Firmar (G,P,G^x)
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(K_w_minus);
        firma.update(G);
        firma.update(P);
        firma.update(Gx);
        byte[] firmaBytes = firma.sign();

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

        String tablaServicios = "1: Servicio_A\n2: Servicio_B\n3: Servicio_C";
        byte[] tablaCifrada = aesCipher.doFinal(tablaServicios.getBytes());

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
        byte[] hmacCheck = hmac.doFinal(servicioCifrado);
        if (!Arrays.equals(hmacServicio, hmacCheck)) {
            socket.close();
            return;
        }

        aesCipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
        byte[] servicioYCliente = aesCipher.doFinal(servicioCifrado);
        String recibido = new String(servicioYCliente);
        System.out.println("Petición recibida: " + recibido);

        // 16. Cifrar IP servidor + puerto servidor y mandar HMAC
        aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
        String ipServidor = "127.0.0.1:8080";
        byte[] respuestaCifrada = aesCipher.doFinal(ipServidor.getBytes());

        byte[] hmacRespuesta = hmac.doFinal(respuestaCifrada);

        out.writeInt(respuestaCifrada.length);
        out.write(respuestaCifrada);
        out.writeInt(hmacRespuesta.length);
        out.write(hmacRespuesta);

        // 18. Enviar "OK"
        out.writeUTF("OK");

        socket.close();
        servidor.close();
    }
}
