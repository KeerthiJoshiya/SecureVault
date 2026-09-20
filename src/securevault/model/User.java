package securevault.model;

import java.util.UUID;

/** Persisted authentication metadata; contains no plaintext login password. */
public final class User {
    private final UUID id;
    private final String username;
    private final byte[] salt;
    private final byte[] passwordHash;
    private final byte[] vaultSalt;
    private final int failedAttempts;
    private final long lockedUntil;

    public User(UUID id, String username, byte[] salt, byte[] passwordHash,
                byte[] vaultSalt, int failedAttempts, long lockedUntil) {
        if (id == null || username == null || !username.matches("[a-z0-9][a-z0-9._@+\\-]{2,79}")
                || salt.length != 16 || vaultSalt.length != 16 || passwordHash.length != 32
                || failedAttempts < 0 || failedAttempts > 5 || lockedUntil < 0) {
            throw new IllegalArgumentException("Invalid user metadata.");
        }
        this.id = id;
        this.username = username;
        this.salt = salt.clone();
        this.passwordHash = passwordHash.clone();
        this.vaultSalt = vaultSalt.clone();
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
    }

    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public byte[] getSalt() { return salt.clone(); }
    public byte[] getPasswordHash() { return passwordHash.clone(); }
    public byte[] getVaultSalt() { return vaultSalt.clone(); }
    public int getFailedAttempts() { return failedAttempts; }
    public long getLockedUntil() { return lockedUntil; }

    public User withLoginState(int attempts, long until) {
        return new User(id, username, salt, passwordHash, vaultSalt, attempts, until);
    }
}
