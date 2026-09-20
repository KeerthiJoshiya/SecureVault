package securevault;

import securevault.ui.ConsoleUI;

/** Application entry point. */
public final class Main {
    private Main() { }

    public static void main(String[] args) {
        new ConsoleUI().run();
    }
}
