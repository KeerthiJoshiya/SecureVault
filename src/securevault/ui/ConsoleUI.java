package securevault.ui;

import java.io.BufferedReader;
import java.io.Console;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import securevault.enums.AccountType;
import securevault.enums.PasswordStrength;
import securevault.exception.ValidationException;
import securevault.model.Account;
import securevault.model.AccountAnalysis;
import securevault.model.SecurityReport;
import securevault.persistence.FileStore;
import securevault.security.SecurityAnalysisEngine;
import securevault.service.AccountService;
import securevault.service.AuthenticationService;

/** Console presentation only: business rules live in services and checkers. */
public final class ConsoleUI {
    private final Console console = System.console();
    private final BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final AuthenticationService authentication;
    private final SecurityAnalysisEngine analysis = new SecurityAnalysisEngine();

    public ConsoleUI(FileStore store) { authentication = new AuthenticationService(store); }

    public void run() throws IOException {
        heading("SecureVault");
        System.out.println("Personal Digital Security Advisor | Java PBL");
        System.out.println("Use fictional credentials for demonstrations.");
        if (console == null) { System.out.println("This console cannot hide password input; use run.cmd in a terminal for hidden entry."); }
        try {
            while (true) {
                System.out.println("\n1. Login\n2. Register\n0. Exit");
                String choice = read("Choose: ").strip();
                try {
                    switch (choice) {
                        case "1" -> login();
                        case "2" -> register();
                        case "0" -> { System.out.println("Goodbye."); return; }
                        default -> System.out.println("Please choose 1, 2 or 0.");
                    }
                } catch (ValidationException exception) {
                    System.out.println(exception.getMessage());
                } catch (EOFException exception) {
                    throw exception;
                } catch (IOException exception) {
                    fileError(exception);
                } catch (GeneralSecurityException exception) {
                    cryptoError();
                }
            }
        } catch (EOFException exception) {
            System.out.println("\nInput ended. Saved changes are preserved. Goodbye.");
        }
    }

    private void register() throws IOException, ValidationException, GeneralSecurityException {
        heading("Register");
        String username = read("Username/email: ");
        System.out.println("Login password: 12-256 characters. Keep it safe; there is no password recovery.");
        char[] password = readPassword("Password: ");
        char[] confirmation = null;
        try {
            confirmation = readPassword("Confirm password: ");
            if (!Arrays.equals(password, confirmation)) { throw new ValidationException("Passwords do not match."); }
            authentication.register(username, password);
            System.out.println("Registration complete. Choose Login to open your vault.");
        } finally {
            Arrays.fill(password, '\0');
            if (confirmation != null) { Arrays.fill(confirmation, '\0'); }
        }
    }

    private void login() throws IOException, ValidationException, GeneralSecurityException {
        heading("Login");
        String username = read("Username/email: ");
        char[] password = readPassword("Password: ");
        AccountService session;
        try { session = authentication.login(username, password); }
        finally { Arrays.fill(password, '\0'); }
        try (session) { sessionMenu(session); }
    }

    private void sessionMenu(AccountService session) throws IOException {
        System.out.println("\nWelcome, " + session.getUsername() + ".");
        while (true) {
            heading("Main menu");
            System.out.println("1. Add account\n2. View accounts\n3. Update account\n4. Delete account"
                    + "\n5. Search accounts\n6. Security report\n7. Recommendations\n0. Logout");
            String choice = read("Choose: ").strip();
            try {
                switch (choice) {
                    case "1" -> add(session);
                    case "2" -> showAccounts(session.list());
                    case "3" -> update(session);
                    case "4" -> delete(session);
                    case "5" -> showAccounts(session.search(read("Search platform, username or category: ")));
                    case "6" -> report(analysis.analyze(session.list()));
                    case "7" -> recommendations(analysis.analyze(session.list()));
                    case "0" -> { System.out.println("Logged out. All successful changes are saved."); return; }
                    default -> System.out.println("Please choose a listed menu number.");
                }
            } catch (ValidationException exception) {
                System.out.println(exception.getMessage());
            } catch (EOFException exception) {
                throw exception;
            } catch (IOException exception) {
                fileError(exception);
            } catch (GeneralSecurityException exception) {
                cryptoError();
            }
        }
    }

    private void add(AccountService session) throws IOException, ValidationException, GeneralSecurityException {
        heading("Add account");
        String platform = read("Platform: ");
        String username = read("Account username/email: ");
        AccountType type = readType(null);
        char[] password = readPassword("Account password: ");
        try {
            session.add(platform, username, type, password);
            System.out.println("Account added and saved.");
        } finally { Arrays.fill(password, '\0'); }
    }

    private void update(AccountService session) throws IOException, ValidationException, GeneralSecurityException {
        Account account = selectAccount(session);
        if (account == null) { return; }
        heading("Update " + account.getPlatform());
        System.out.println("Press Enter to keep any current value.");
        String platform = read("Platform [" + account.getPlatform() + "]: ");
        String username = read("Username/email [" + account.getUsername() + "]: ");
        AccountType type = readType(account.getType());
        char[] password = readPassword("New account password [Enter to keep]: ");
        if (password.length == 0) { password = account.copyPassword(); }
        try {
            session.update(account.getId(), platform.isBlank() ? account.getPlatform() : platform,
                    username.isBlank() ? account.getUsername() : username, type, password);
            System.out.println("Account updated and saved.");
        } finally { Arrays.fill(password, '\0'); }
    }

    private void delete(AccountService session) throws IOException, ValidationException, GeneralSecurityException {
        Account account = selectAccount(session);
        if (account == null) { return; }
        String answer = read("Delete " + account.getPlatform() + " (" + account.getUsername() + ")? Type yes: ");
        if (!answer.strip().equalsIgnoreCase("yes")) { System.out.println("Deletion cancelled."); return; }
        session.delete(account.getId());
        System.out.println("Account deleted and saved.");
    }

    private Account selectAccount(AccountService session) throws IOException, ValidationException {
        List<Account> accounts = session.list();
        showAccounts(accounts);
        if (accounts.isEmpty()) { return null; }
        int selection = number(read("Account number (0 to cancel): "), 0, accounts.size());
        return selection == 0 ? null : accounts.get(selection - 1);
    }

    private AccountType readType(AccountType current) throws IOException, ValidationException {
        AccountType[] types = AccountType.values();
        for (int i = 0; i < types.length; i++) { System.out.print((i + 1) + ". " + types[i] + "  "); }
        System.out.println();
        String value = read(current == null ? "Category: " : "Category [" + current + "]: ").strip();
        if (value.isEmpty() && current != null) { return current; }
        return types[number(value, 1, types.length) - 1];
    }

    private int number(String value, int minimum, int maximum) throws ValidationException {
        try {
            int parsed = Integer.parseInt(value.strip());
            if (parsed >= minimum && parsed <= maximum) { return parsed; }
        } catch (NumberFormatException ignored) {
            // Translate a parsing error into a useful input-validation message.
        }
        throw new ValidationException("Enter a whole number from " + minimum + " to " + maximum + ".");
    }

    private void showAccounts(List<Account> accounts) {
        heading("Accounts");
        if (accounts.isEmpty()) { System.out.println("No matching accounts. Add an account to get started."); return; }
        for (int i = 0; i < accounts.size(); i++) {
            Account account = accounts.get(i);
            System.out.println((i + 1) + ". " + account.getPlatform() + " | " + account.getUsername()
                    + " | " + account.getType() + " | Password: [hidden]");
        }
    }

    private void report(SecurityReport report) {
        heading("Security report");
        if (report.getAnalyses().isEmpty()) { System.out.println("Score: N/A. Add an account before running analysis."); return; }
        System.out.println("Generated: " + report.getGeneratedAt());
        System.out.println("Total accounts       : " + report.getAnalyses().size());
        for (PasswordStrength strength : PasswordStrength.values()) {
            System.out.printf("%-21s: %d%n", strength, report.countStrength(strength));
        }
        System.out.println("Accounts with reuse  : " + report.getReusedAccountCount());
        System.out.println("Similar passwords    : " + report.getSimilarPasswordAccountCount());
        System.out.println("Accounts with patterns: " + report.getPatternAccountCount());
        System.out.println("High/critical risk   : " + report.getHighRiskCount());
        System.out.println("Security score       : " + report.getScore() + "/100");
        System.out.println("\nEducational rule-based score; not a guarantee of security.");
        for (AccountAnalysis result : report.getAnalyses()) {
            System.out.println("\n" + result.getPlatform() + " | " + result.getUsername());
            System.out.println("  " + result.getStrength() + " | Risk: " + result.getRisk() + " | Score: " + result.getScore());
            System.out.println("  Calculation: " + result.getStrength().getBaseScore() + " - "
                    + result.getReusePenalty() + " reuse - " + result.getSimilarityPenalty()
                    + " similarity - " + result.getPatternPenalty() + " patterns = " + result.getScore());
            if (result.getReuseCount() > 1) { System.out.println("  Password reused across " + result.getReuseCount() + " accounts."); }
            result.getSimilarPasswords().forEach(match -> System.out.println("  - Similar to "
                    + match.otherPlatform() + " (" + match.reason() + ")"));
            for (String pattern : result.getPatterns()) { System.out.println("  - " + pattern); }
        }
        recommendations(report);
    }

    private void recommendations(SecurityReport report) {
        heading("Recommendations");
        if (report.getAnalyses().isEmpty()) { System.out.println("Add an account to receive personalized advice."); return; }
        for (int i = 0; i < report.getRecommendations().size(); i++) {
            System.out.println((i + 1) + ". " + report.getRecommendations().get(i));
        }
    }

    private String read(String prompt) throws IOException {
        String value;
        if (console != null) { value = console.readLine("%s", prompt); }
        else { System.out.print(prompt); System.out.flush(); value = input.readLine(); }
        if (value == null) { throw new EOFException(); }
        return value;
    }

    private char[] readPassword(String prompt) throws IOException {
        if (console == null) { return read(prompt).toCharArray(); }
        char[] password = console.readPassword("%s", prompt);
        if (password == null) { throw new EOFException(); }
        return password;
    }

    private void heading(String title) { System.out.println("\n--- " + title + " ---"); }
    private void fileError(IOException exception) { System.out.println("File operation failed: " + exception.getMessage()); }
    private void cryptoError() { System.out.println("Vault security check failed. Data may be damaged; existing files were not reset."); }
}
