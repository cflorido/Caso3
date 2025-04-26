import java.net.ServerSocket;
import java.net.Socket;

public class ServidorConcurrente {
    private static final int PUERTO = 5000;

    public void iniciar(int cantidadDelegados) {
        try {
            ServerSocket servidor = new ServerSocket(PUERTO);
            System.out.println("Servidor concurrente iniciado en el puerto " + PUERTO);

            int delegadosIniciados = 0;

            while (delegadosIniciados < cantidadDelegados) {
                Socket socketCliente = servidor.accept();
                System.out.println("Cliente conectado. Creando delegado...");

                ServidorDelegado delegado = new ServidorDelegado(socketCliente);
                delegado.start();

                delegadosIniciados++;
            }

            System.out.println("Se iniciaron todos los delegados. Cerrando servidor de aceptación.");
            servidor.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
