package securevault;

import java.util.UUID;
import java.util.List;
import java.util.Arrays;
import java.util.Comparator;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import securevault.enums.AccountType;
import securevault.enums.PasswordStrength;
import securevault.enums.RiskLevel;
import securevault.exception.ValidationException;
import securevault.model.Account;
import securevault.model.SecurityReport;
import securevault.security.PasswordStrengthChecker;
import securevault.security.SecurityAnalysisEngine;
import securevault.security.PasswordHasher;
import securevault.security.VaultEncryption;
import securevault.persistence.FileStore;
import securevault.service.AccountService;
import securevault.service.AuthenticationService;
import securevault.ui.UiComponentChecks;

/** Small executable checks; assertions remain active without the -ea option. */
public final class TestRunner {
    private static int checks;

    public static void main(String[] args) throws Exception {
        char[] input = "Example@123".toCharArray();
        Account account = new Account(UUID.randomUUID(), " Mail ", "student", AccountType.EMAIL, input);
        input[0] = 'X';
        check(account.copyPassword()[0] == 'E', "Constructor must copy passwords");
        char[] copy = account.copyPassword();
        copy[0] = 'X';
        check(account.copyPassword()[0] == 'E', "Getter must copy passwords");
        check(account.getPlatform().equals("Mail"), "Platform should be trimmed");
        check(!account.toString().contains("Example@123"), "Display must omit passwords");
        try {
            new Account(UUID.randomUUID(), " ", "student", AccountType.EMAIL, input);
            throw new AssertionError("Blank platform accepted");
        } catch (ValidationException expected) {
            checks++;
        }
        analysisChecks();
        encryptionChecks();
        persistenceChecks();
        consoleChecks();
        check(UiComponentChecks.run() == 6, "Reusable Swing controls pass layout and contrast checks");
        System.out.println("PASS: " + checks + " checks");
    }

    private static void encryptionChecks() throws Exception {
        PasswordHasher hasher = new PasswordHasher();
        char[] password = "Fictional-login!842".toCharArray();
        byte[] salt = hasher.newSalt();
        byte[] hash = hasher.derive(password, salt);
        check(hasher.verify(password, salt, hash), "Correct password verifies");
        check(!hasher.verify("incorrect".toCharArray(), salt, hash), "Wrong password does not verify");
        check(!Arrays.equals(hash, hasher.derive(password, hasher.newSalt())), "Salt changes derived value");
        VaultEncryption crypto = new VaultEncryption();
        UUID owner = UUID.randomUUID();
        byte[] plain = "fictional-private-data".getBytes(StandardCharsets.UTF_8);
        byte[] first = crypto.encrypt(plain, hash, owner);
        byte[] second = crypto.encrypt(plain, hash, owner);
        check(!Arrays.equals(first, second), "Every encryption uses a fresh nonce");
        check(Arrays.equals(plain, crypto.decrypt(first, hash, owner)), "Encrypted content round trips");
        expect(GeneralSecurityException.class, () -> crypto.decrypt(first, hash, UUID.randomUUID()), "Owner binding");
        expect(GeneralSecurityException.class, () -> crypto.decrypt(first, new byte[32], owner), "Wrong encryption key");
        first[first.length - 1] ^= 1;
        expect(GeneralSecurityException.class, () -> crypto.decrypt(first, hash, owner), "Tampered vault is rejected");
        expect(GeneralSecurityException.class, () -> crypto.decrypt(new byte[3], hash, owner), "Truncated vault is rejected");
    }

    private static void consoleChecks() throws Exception {
        Path root = Files.createTempDirectory("securevault-console-tests-");
        try {
            String first = runConsole(root, List.of(
                    "invalid", "2", "demo_student", "DemoLogin!8427", "mismatch",
                    "2", "demo_student", "DemoLogin!8427", "DemoLogin!8427",
                    "1", "demo_student", "DemoLogin!8427", "6",
                    "1", "Mail", "learner", "1", "Welcome@123",
                    "1", "Social", "learner", "2", "Welcome@123",
                    "1", "Work", "learner", "4", "V9!mR2$kL7&zP4@x",
                    "6", "3", "2", "", "", "", "T6!vN8$bH2&jC5@r",
                    "6", "4", "1", "no", "5", "mail", "0", "0"));
            check(first.contains("Please choose 1, 2 or 0."), "Invalid main menu input handled");
            check(first.contains("Passwords do not match."), "Registration confirmation handled");
            check(first.contains("Score: N/A"), "Empty vault UI does not claim a score");
            check(first.contains("Security score       : 43/100"), "Presentation example starts at 43");
            check(first.contains("Security score       : 80/100"), "Update refreshes score to 80");
            check(first.contains("Deletion cancelled."), "Delete requires confirmation");
            check(!first.contains("Welcome@123") && !first.contains("DemoLogin!8427"), "Output does not print passwords");
            String second = runConsole(root, List.of("1", "demo_student", "DemoLogin!8427",
                    "2", "3", "9999999999999999999999999", "4", "1", "yes", "6", "0", "0"));
            check(second.contains("Social | learner | SOCIAL | Password: [hidden]"), "CLI restart restores accounts");
            check(second.contains("Enter a whole number from 0 to 3."), "Oversized numeric input is handled");
            check(second.contains("Account deleted and saved."), "Confirmed deletion works through UI");
            check(second.contains("Security score       : 100/100"), "Report recalculates after deletion");
            String eof = runConsole(root, List.of("1", "demo_student", "DemoLogin!8427"));
            check(eof.contains("Input ended."), "EOF during a session exits cleanly");
            String afterEof = runConsole(root, List.of("0"));
            check(afterEof.contains("Goodbye."), "EOF releases file lock for next process");
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) { Files.deleteIfExists(path); }
            }
        }
    }

    private static String runConsole(Path root, List<String> input) throws Exception {
        String javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Path output = root.resolve(UUID.randomUUID() + ".txt");
        Process process = new ProcessBuilder(javaExecutable, "-cp", System.getProperty("java.class.path"),
                "securevault.Main", "--console", root.resolve("data").toString())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            try (var stdin = process.getOutputStream()) {
                stdin.write((String.join("\n", input) + "\n").getBytes(StandardCharsets.UTF_8));
            }
            if (!process.waitFor(45, java.util.concurrent.TimeUnit.SECONDS)) {
                throw new AssertionError("Console flow timed out");
            }
            String text = Files.readString(output);
            if (process.exitValue() != 0) { throw new AssertionError("Console failed: " + text); }
            return text;
        } finally {
            if (process.isAlive()) { process.destroyForcibly().waitFor(); }
        }
    }

    private static void persistenceChecks() throws Exception {
        Path root = Files.createTempDirectory("securevault-tests-");
        char[] password = "Fictional-login!842".toCharArray();
        Clock now = Clock.fixed(Instant.parse("2026-09-20T12:00:00Z"), ZoneOffset.UTC);
        UUID accountId;
        UUID userId;
        try {
            try (FileStore store = new FileStore(root)) {
                expect(IOException.class, () -> { try (FileStore ignored = new FileStore(root)) { } }, "Second instance is blocked");
                AuthenticationService auth = new AuthenticationService(store, now);
                expect(ValidationException.class, () -> auth.register("alice", "short".toCharArray()), "Short login password rejected");
                auth.register("Alice", password);
                userId = store.loadUsers().get(0).getId();
                expect(ValidationException.class, () -> auth.register("ALICE", password), "Usernames are case-insensitive");
                try (AccountService session = auth.login("alice", password)) {
                    check(session.list().isEmpty(), "New user starts with empty vault");
                    session.add("Mail", "student@example.com", AccountType.EMAIL, "Welcome@123".toCharArray());
                    accountId = session.list().get(0).getId();
                    expect(ValidationException.class, () -> session.add("MAIL", "STUDENT@example.com", AccountType.EMAIL,
                            "other".toCharArray()), "Duplicate platform and username rejected");
                    check(session.search("MAIL").size() == 1, "Search is case-insensitive");
                    check(session.search("banking").isEmpty(), "Search has no false match");
                    Path vault = root.resolve(userId + ".vault");
                    check(!new String(Files.readAllBytes(vault), StandardCharsets.ISO_8859_1).contains("Welcome@123"),
                            "No plaintext account password on disk");
                    check(!Files.readString(root.resolve("users.properties")).contains(new String(password)),
                            "No plaintext login password on disk");
                    // Force replacement failure without relying on OS-specific file permissions.
                    Path backup = root.resolve("test-backup.vault");
                    Files.move(vault, backup);
                    Files.createDirectory(vault);
                    Files.writeString(vault.resolve("blocker"), "test");
                    try {
                        expect(IOException.class, () -> session.delete(accountId), "Failed save is reported");
                        check(session.list().size() == 1, "Failed delete preserves session state");
                    } finally {
                        Files.delete(vault.resolve("blocker"));
                        Files.delete(vault);
                        Files.move(backup, vault);
                    }
                }
                expect(ValidationException.class, () -> auth.login("alice", "bad".toCharArray()), "Failed login is recorded");
                check(store.loadUsers().get(0).getFailedAttempts() == 1, "Failed login persisted");
            }
            try (FileStore store = new FileStore(root)) {
                AuthenticationService auth = new AuthenticationService(store, now);
                check(store.loadUsers().get(0).getFailedAttempts() == 1, "Failed attempts survive restart");
                for (int i = 0; i < 4; i++) {
                    expect(ValidationException.class, () -> auth.login("alice", "bad".toCharArray()), "Wrong password rejected");
                }
                check(store.loadUsers().get(0).getLockedUntil() == now.instant().getEpochSecond() + 60, "Fifth failure starts lock");
                expect(ValidationException.class, () -> auth.login("alice", password), "Correct password cannot bypass active lock");
            }
            try (FileStore store = new FileStore(root)) {
                AuthenticationService lockedAuth = new AuthenticationService(store, now);
                expect(ValidationException.class, () -> lockedAuth.login("alice", password), "Lock survives restart");
                AuthenticationService auth = new AuthenticationService(store, Clock.offset(now, java.time.Duration.ofSeconds(61)));
                try (AccountService session = auth.login("alice", password)) {
                    check(session.list().size() == 1, "Account survives restart");
                    check(session.list().get(0).getId().equals(accountId), "Stable account ID survives restart");
                    check(store.loadUsers().get(0).getFailedAttempts() == 0, "Successful login resets failures");
                    session.update(accountId, "Private Mail", "student@example.com", AccountType.EMAIL,
                            "V9!mR2$kL7&zP4@x".toCharArray());
                }
                try (AccountService session = auth.login("alice", password)) {
                    check(session.list().get(0).getPlatform().equals("Private Mail"), "Update persists");
                    check(new SecurityAnalysisEngine().analyze(session.list()).getScore() == 100, "Updated password is analyzed");
                }
                auth.register("bob", password);
                try (AccountService bob = auth.login("bob", password)) {
                    check(bob.list().isEmpty(), "Users have separate vaults");
                    expect(ValidationException.class, () -> bob.delete(accountId), "Cannot delete another user's account");
                }
                Path vault = root.resolve(userId + ".vault");
                byte[] original = Files.readAllBytes(vault);
                byte[] changed = original.clone();
                changed[changed.length - 1] ^= 1;
                Files.write(vault, changed);
                expect(GeneralSecurityException.class, () -> auth.login("alice", password), "Corrupt vault blocks login");
                check(Arrays.equals(changed, Files.readAllBytes(vault)), "Corrupt vault is not silently replaced");
                Files.write(vault, original);
                Files.move(vault, root.resolve("missing-test.vault"));
                expect(IOException.class, () -> auth.login("alice", password), "Missing vault blocks login");
                check(!Files.exists(vault), "Missing vault is not silently recreated");
                Files.move(root.resolve("missing-test.vault"), vault);
                try (AccountService session = auth.login("alice", password)) { session.delete(accountId); }
                try (AccountService session = auth.login("alice", password)) {
                    check(session.list().isEmpty(), "Delete persists");
                    session.close();
                    expect(IllegalStateException.class, session::list, "Closed session cannot be reused");
                }
                Path registry = root.resolve("users.properties");
                byte[] metadata = Files.readAllBytes(registry);
                Files.writeString(registry, "version=broken");
                expect(IOException.class, store::loadUsers, "Damaged registry is rejected");
                check(Files.readString(registry).equals("version=broken"), "Registry is not silently reset");
                Files.write(registry, metadata);
            }
        } finally {
            Arrays.fill(password, '\0');
            // This tree was created by this test; never touch the real data directory.
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) { Files.deleteIfExists(path); }
            }
        }
    }

    @FunctionalInterface
    private interface CheckedAction { void run() throws Exception; }

    private static void expect(Class<? extends Exception> type, CheckedAction action, String message) throws Exception {
        try { action.run(); }
        catch (Exception exception) {
            if (type.isInstance(exception)) { checks++; return; }
            throw new AssertionError(message + ": unexpected exception", exception);
        }
        throw new AssertionError(message + ": expected " + type.getSimpleName());
    }

    private static void analysisChecks() throws Exception {
        PasswordStrengthChecker strength = new PasswordStrengthChecker();
        check(strength.classify("abc".toCharArray()) == PasswordStrength.WEAK, "Short passwords are weak");
        check(strength.classify("Abcdefg2".toCharArray()) == PasswordStrength.MODERATE, "Eight-character boundary");
        check(strength.classify("Abcdefghijk2".toCharArray()) == PasswordStrength.STRONG, "Twelve-character boundary");
        check(strength.classify("V9!mR2$kL7&zP4@x".toCharArray()) == PasswordStrength.VERY_STRONG, "Sixteen-character boundary");
        Account first = account("Mail", "student", "Welcome@123");
        Account second = account("Social", "student", "Welcome@123");
        SecurityAnalysisEngine engine = new SecurityAnalysisEngine();
        SecurityReport report = engine.analyze(List.of(first, second));
        check(report.getReusedAccountCount() == 2, "Both reused accounts are counted");
        check(report.getAnalyses().get(0).getReuseCount() == 2, "Reuse includes this account");
        check(report.getScore() == 15, "Example score is calculated correctly");
        check(report.getHighRiskCount() == 2, "Critical accounts count as high-risk");
        check(report.getAnalyses().get(0).getRisk() == RiskLevel.CRITICAL, "Critical risk threshold");
        check(report.getAnalyses().get(0).getReusePenalty() == 25, "Two-account reuse penalty");
        check(report.getAnalyses().get(0).getPatternPenalty() == 20, "Pattern penalty is capped");
        check(report.getAnalyses().get(0).getPatterns().size() == 2, "Common word and sequence detected");
        check(!report.getRecommendations().isEmpty(), "Findings create advice");
        SecurityReport empty = engine.analyze(List.of());
        check(empty.getAnalyses().isEmpty() && empty.getRecommendations().isEmpty(), "Empty vault has no findings");
        // These strings have the same Arrays.hashCode(char[]) but are not equal.
        report = engine.analyze(List.of(account("A", "student", "Aa"), account("B", "student", "BB")));
        check(report.getReusedAccountCount() == 0, "Hash collision must not cause false reuse");
        report = engine.analyze(List.of(account("Mail", "Keerthi@example.com", "KEERTHI!987aaa2026qwe")));
        check(report.getAnalyses().get(0).getPatterns().size() == 5, "Username, reverse digits, repeats, year, keyboard");
        report = engine.analyze(List.of(account("Work", "student", "V9!mR2$kL7&zP4@x")));
        check(report.getScore() == 100 && report.getHighRiskCount() == 0, "Clean unique password score");
        report = engine.analyze(List.of(account("A", "first", "Ax7!mN4$pQ2z"),
                account("B", "second", "Ax7!mN4$pQ2z")));
        check(report.getScore() == 55, "Strong password reused twice keeps a nonzero explainable score");
        check(report.getAnalyses().get(0).getRisk() == RiskLevel.MEDIUM, "Strong reused password is medium risk");
    }

    private static Account account(String platform, String username, String password) throws Exception {
        return new Account(UUID.randomUUID(), platform, username, AccountType.OTHER, password.toCharArray());
    }

    private static void check(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
        checks++;
    }
}
