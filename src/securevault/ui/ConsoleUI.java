package securevault.ui;

import java.util.Scanner;

/** Keeps menu interaction separate from domain objects. */
public final class ConsoleUI {
    public void run() {
        Scanner input = new Scanner(System.in);
        System.out.println("\nSecureVault | Personal Digital Security Advisor");
        while (true) {
            System.out.println("\n1. About SecureVault\n0. Exit");
            System.out.print("Choose: ");
            if (!input.hasNextLine()) {
                break;
            }
            switch (input.nextLine().strip()) {
                case "1" -> System.out.println("Analyze password habits across your online accounts.");
                case "0" -> {
                    System.out.println("Goodbye.");
                    return;
                }
                default -> System.out.println("Please choose 1 or 0.");
            }
        }
    }
}
