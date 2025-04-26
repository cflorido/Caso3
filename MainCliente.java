import java.util.concurrent.CyclicBarrier;

public class MainCliente {
    public static void main(String[] args) {
        String host = "localhost"; // Cambia aquí si tu servidor está en otra IP
        int puerto = 5000; // Cambia aquí por el puerto correcto del servidor

        // Creamos la barrera (aunque solo sea para 1 cliente en este caso)
        CyclicBarrier barrera = new CyclicBarrier(1);

        // Creamos y arrancamos el Cliente
        ClienteIterativo cliente = new ClienteIterativo(host, puerto, barrera);
        cliente.start();
    }
}
