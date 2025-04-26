import java.io.File;
import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.CyclicBarrier;

public class MainServidor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=== Menu de Servidor ===");
        System.out.println("1. Iniciar Servidor Normal");
        System.out.println("2. Iniciar Servidor Concurrente (Delegados)");
        System.out.print("Elige una opcion: ");
        int opcion = scanner.nextInt();

        switch (opcion) {
            case 1:
                try {
                    ServidorNormal servidorNormal = new ServidorNormal();
                    Thread servidorThread = new Thread(() -> {
                        try {
                            servidorNormal.iniciar();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                    servidorThread.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    Thread.sleep(1000);

                    String host = "localhost";
                    int puerto = 5001;
                    CyclicBarrier barrera = new CyclicBarrier(1);
                    ClienteIterativo cliente = new ClienteIterativo(host, puerto, barrera);
                    cliente.start();

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case 2:
                System.out.println("Cuantos delegados deseas usar? (4, 16, 32 o 64): ");
                int numDelegados = scanner.nextInt();

                if (numDelegados != 4 && numDelegados != 16 && numDelegados != 32 && numDelegados != 64) {
                    System.out.println("Número inválido de delegados. Solo se permite 4, 16, 32 o 64.");
                    break;
                }

                try {

                    ServidorConcurrente servidorConcurrente = new ServidorConcurrente();
                    Thread servidorThread = new Thread(() -> {
                        try {
                            servidorConcurrente.iniciar(numDelegados);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                    servidorThread.start();

                    Thread.sleep(1000);

                    for (int i = 0; i < numDelegados; i++) {
                        ClienteDelegado cliente = new ClienteDelegado("127.0.0.1", 5000);
                        cliente.start();
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            default:
                System.out.println("Opción inválida.");
        }
        scanner.close();
    }
}
