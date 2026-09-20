package securevault;

import securevault.persistence.FileStore;
import securevault.ui.ConsoleUI;
import securevault.ui.SwingUI;
import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/** Application entry point. */
public final class Main {
    private Main() { }

    public static void main(String[] args) {
        boolean consoleMode = args.length > 0 && args[0].equals("--console");
        int pathIndex = consoleMode ? 1 : 0;
        if (args.length > pathIndex + 1) {
            System.err.println("Usage: java -cp out securevault.Main [--console] [data-directory]");
            System.exit(1);
        }
        Path dataPath;
        try {
            dataPath = Path.of(args.length == pathIndex ? "data" : args[pathIndex]);
        } catch (InvalidPathException exception) {
            System.err.println("Invalid data directory: " + exception.getMessage());
            return;
        }
        if (consoleMode) {
            runConsole(dataPath);
        } else {
            SwingUtilities.invokeLater(() -> runDesktop(dataPath));
        }
    }

    private static void runConsole(Path dataPath) {
        try (FileStore store = new FileStore(dataPath)) {
            store.loadUsers();
            new ConsoleUI(store).run();
        } catch (IOException exception) {
            System.err.println("Cannot open SecureVault: " + exception.getMessage());
        }
    }

    private static void runDesktop(Path dataPath) {
        try {
            FileStore store = new FileStore(dataPath);
            try {
                store.loadUsers();
                new SwingUI(store).show();
            } catch (RuntimeException | IOException exception) {
                store.close();
                throw exception;
            }
        } catch (IOException exception) {
            JOptionPane.showMessageDialog(null, "Cannot open SecureVault:\n" + exception.getMessage(),
                    "SecureVault", JOptionPane.ERROR_MESSAGE);
        }
    }
}
