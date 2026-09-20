package securevault.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import securevault.exception.ValidationException;
import securevault.model.User;
import securevault.persistence.FileStore;
import securevault.security.PasswordHasher;

public final class AuthenticationService {
    public static final int MAX_ATTEMPTS = 5;
    public static final long LOCK_SECONDS = 60;
    private final FileStore store;
    private final Clock clock;
    private final PasswordHasher hasher = new PasswordHasher();

    public AuthenticationService(FileStore store) { this(store, Clock.systemUTC()); }

    /** An injectable clock makes lock expiry testable without waiting. */
    public AuthenticationService(FileStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public void register(String username, char[] password)
            throws ValidationException, IOException, GeneralSecurityException {
        String normalized = normalize(username);
        if (password == null || password.length < 12 || password.length > 256
                || allWhitespace(password)) {
            throw new ValidationException("Login password must contain 12 to 256 characters and cannot be all whitespace.");
        }
        List<User> users = store.loadUsers();
        if (users.size() >= 1000) { throw new ValidationException("User limit reached."); }
        if (users.stream().anyMatch(user -> user.getUsername().equals(normalized))) {
            throw new ValidationException("Username/email is already registered.");
        }
        byte[] salt = hasher.newSalt();
        byte[] vaultSalt = hasher.newSalt();
        byte[] hash = hasher.derive(password, salt);
        byte[] key = null;
        try {
            key = hasher.derive(password, vaultSalt);
            User user = new User(UUID.randomUUID(), normalized, salt, hash, vaultSalt, 0, 0);
            // Publish the registry entry only after an encrypted empty vault exists.
            store.saveAccounts(user, key, List.of());
            users.add(user);
            store.saveUsers(users);
        } finally {
            Arrays.fill(hash, (byte) 0);
            if (key != null) { Arrays.fill(key, (byte) 0); }
        }
    }

    public AccountService login(String username, char[] password)
            throws ValidationException, IOException, GeneralSecurityException {
        String normalized = normalize(username);
        if (password == null || password.length == 0 || password.length > 256) {
            throw new ValidationException("Enter a login password of 1 to 256 characters.");
        }
        List<User> users = store.loadUsers();
        for (int i = 0; i < users.size(); i++) {
            User user = users.get(i);
            if (!user.getUsername().equals(normalized)) { continue; }
            long now = clock.instant().getEpochSecond();
            if (user.getLockedUntil() > now) {
                throw new ValidationException("Login locked. Try again in " + (user.getLockedUntil() - now) + " seconds.");
            }
            if (!hasher.verify(password, user.getSalt(), user.getPasswordHash())) {
                int previous = user.getLockedUntil() > 0 ? 0 : user.getFailedAttempts();
                int attempts = previous + 1;
                boolean locked = attempts >= MAX_ATTEMPTS;
                users.set(i, user.withLoginState(attempts, locked ? now + LOCK_SECONDS : 0));
                store.saveUsers(users);
                throw new ValidationException(locked ? "Too many failed attempts. Login locked for 60 seconds."
                        : "Invalid username or password. Attempts remaining: " + (MAX_ATTEMPTS - attempts));
            }
            byte[] key = hasher.derive(password, user.getVaultSalt());
            AccountService session = null;
            try {
                session = new AccountService(user, key, store);
                users.set(i, user.withLoginState(0, 0));
                store.saveUsers(users);
                return session;
            } catch (IOException | GeneralSecurityException exception) {
                if (session != null) { session.close(); }
                throw exception;
            } finally { Arrays.fill(key, (byte) 0); }
        }
        throw new ValidationException("Invalid username or password.");
    }

    private static String normalize(String username) throws ValidationException {
        String value = username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
        if (!value.matches("[a-z0-9][a-z0-9._@+\\-]{2,79}")) {
            throw new ValidationException("Username/email: 3-80 letters, digits or . _ @ + -; start with a letter or digit.");
        }
        return value;
    }

    private static boolean allWhitespace(char[] password) {
        for (char c : password) { if (!Character.isWhitespace(c)) { return false; } }
        return true;
    }
}
