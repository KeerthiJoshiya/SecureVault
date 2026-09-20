package securevault;

import securevault.ui.ConsoleUI;
import securevault.persistence.FileStore;
import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/** Application entry point. */
public final class Main {
    private Main() { }

    public static void main(String[] args) {
        if (args.length > 1) {
            System.err.println("Usage: java -cp out securevault.Main [data-directory]");
            System.exit(1);
        }
        try (FileStore store = new FileStore(Path.of(args.length == 0 ? "data" : args[0]))) {
            store.loadUsers();
            new ConsoleUI(store).run();
        } catch (IOException | InvalidPathException exception) {
            System.err.println("Cannot open SecureVault: " + exception.getMessage());
            System.exit(1);
        }
    }
}
