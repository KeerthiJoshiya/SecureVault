package securevault.persistence;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import securevault.enums.AccountType;
import securevault.exception.ValidationException;
import securevault.model.Account;
import securevault.model.User;
import securevault.security.PasswordHasher;
import securevault.security.VaultEncryption;

/** Owns disk formats and a process lock; never writes plaintext account data. */
public final class FileStore implements AutoCloseable {
    public static final int MAX_ACCOUNTS = 500;
    private static final long MAX_FILE_BYTES = 8 * 1024 * 1024;
    private final Path directory;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private final VaultEncryption encryption = new VaultEncryption();

    public FileStore(Path directory) throws IOException {
        this.directory = directory.toAbsolutePath().normalize();
        Files.createDirectories(this.directory);
        lockChannel = FileChannel.open(this.directory.resolve(".lock"),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        try {
            lock = lockChannel.tryLock();
            if (lock == null) { throw new IOException("This data folder is already open in another SecureVault instance."); }
        } catch (IOException | OverlappingFileLockException exception) {
            lockChannel.close();
            throw new IOException("Cannot lock data folder; close other SecureVault instances.", exception);
        }
    }

    public List<User> loadUsers() throws IOException {
        Path file = directory.resolve("users.properties");
        if (!Files.exists(file)) { return new ArrayList<>(); }
        try {
            Properties properties = new Properties();
            properties.load(new StringReader(new String(readBounded(file), StandardCharsets.UTF_8)));
            if (!required(properties, "version").equals("1")
                    || Integer.parseInt(required(properties, "iterations")) != PasswordHasher.ITERATIONS) {
                throw new IOException("Unsupported user-file format.");
            }
            int count = Integer.parseInt(required(properties, "count"));
            if (count < 0 || count > 1000) { throw new IOException("Invalid user count."); }
            List<User> users = new ArrayList<>();
            Set<UUID> ids = new HashSet<>();
            Set<String> names = new HashSet<>();
            for (int i = 0; i < count; i++) {
                String prefix = "user." + i + ".";
                UUID id = UUID.fromString(required(properties, prefix + "id"));
                String username = required(properties, prefix + "username");
                if (!ids.add(id) || !names.add(username)) { throw new IOException("Duplicate user metadata."); }
                users.add(new User(id, username,
                        decode(properties, prefix + "salt"), decode(properties, prefix + "hash"),
                        decode(properties, prefix + "vaultSalt"),
                        Integer.parseInt(required(properties, prefix + "attempts")),
                        Long.parseLong(required(properties, prefix + "lockedUntil"))));
            }
            return users;
        } catch (IllegalArgumentException exception) {
            throw new IOException("User metadata is damaged. Existing files have not been reset.", exception);
        }
    }

    public void saveUsers(List<User> users) throws IOException {
        Properties properties = new Properties();
        properties.setProperty("version", "1");
        properties.setProperty("iterations", Integer.toString(PasswordHasher.ITERATIONS));
        properties.setProperty("count", Integer.toString(users.size()));
        for (int i = 0; i < users.size(); i++) {
            User user = users.get(i);
            String prefix = "user." + i + ".";
            properties.setProperty(prefix + "id", user.getId().toString());
            properties.setProperty(prefix + "username", user.getUsername());
            properties.setProperty(prefix + "salt", encode(user.getSalt()));
            properties.setProperty(prefix + "hash", encode(user.getPasswordHash()));
            properties.setProperty(prefix + "vaultSalt", encode(user.getVaultSalt()));
            properties.setProperty(prefix + "attempts", Integer.toString(user.getFailedAttempts()));
            properties.setProperty(prefix + "lockedUntil", Long.toString(user.getLockedUntil()));
        }
        StringWriter writer = new StringWriter();
        properties.store(writer, "SecureVault v1 authentication metadata (no plaintext passwords)");
        atomicWrite(directory.resolve("users.properties"), writer.toString().getBytes(StandardCharsets.UTF_8));
    }

    public List<Account> loadAccounts(User user, byte[] key) throws IOException, GeneralSecurityException {
        // A missing vault for an existing user is an error, not an empty replacement.
        byte[] plaintext = encryption.decrypt(readBounded(vaultPath(user)), key, user.getId());
        List<Account> accounts = new ArrayList<>();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            if (input.readInt() != 1) { throw new IOException("Unsupported account-data version."); }
            int count = input.readInt();
            if (count < 0 || count > MAX_ACCOUNTS) { throw new IOException("Invalid account count."); }
            Set<UUID> ids = new HashSet<>();
            for (int i = 0; i < count; i++) {
                UUID id = UUID.fromString(input.readUTF());
                if (!ids.add(id)) { throw new IOException("Duplicate account ID in vault."); }
                String platform = input.readUTF();
                String username = input.readUTF();
                AccountType type = AccountType.valueOf(input.readUTF());
                int length = input.readInt();
                if (length < 1 || length > 1024) { throw new IOException("Invalid password length in vault."); }
                char[] password = new char[length];
                try {
                    for (int j = 0; j < length; j++) { password[j] = input.readChar(); }
                    accounts.add(new Account(id, platform, username, type, password));
                } finally { Arrays.fill(password, '\0'); }
            }
            if (input.read() != -1) { throw new IOException("Unexpected data after vault records."); }
            return accounts;
        } catch (IOException | IllegalArgumentException | ValidationException exception) {
            accounts.forEach(Account::clearPassword);
            throw new IOException("Cannot read vault records. Existing files have not been reset.", exception);
        } finally { Arrays.fill(plaintext, (byte) 0); }
    }

    public void saveAccounts(User user, byte[] key, List<Account> accounts)
            throws IOException, GeneralSecurityException {
        if (accounts.size() > MAX_ACCOUNTS) { throw new IOException("Account limit reached."); }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(1);
            output.writeInt(accounts.size());
            for (Account account : accounts) {
                output.writeUTF(account.getId().toString());
                output.writeUTF(account.getPlatform());
                output.writeUTF(account.getUsername());
                output.writeUTF(account.getType().name());
                char[] password = account.copyPassword();
                try {
                    output.writeInt(password.length);
                    for (char c : password) { output.writeChar(c); }
                } finally { Arrays.fill(password, '\0'); }
            }
        }
        byte[] plaintext = buffer.toByteArray();
        try { atomicWrite(vaultPath(user), encryption.encrypt(plaintext, key, user.getId())); }
        finally { Arrays.fill(plaintext, (byte) 0); }
    }

    private Path vaultPath(User user) { return directory.resolve(user.getId() + ".vault"); }

    private byte[] readBounded(Path file) throws IOException {
        if (Files.size(file) > MAX_FILE_BYTES) { throw new IOException("Data file exceeds the supported size."); }
        return Files.readAllBytes(file);
    }

    private void atomicWrite(Path target, byte[] bytes) throws IOException {
        Path temporary = Files.createTempFile(directory, "save-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) { channel.write(buffer); }
                channel.force(true);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally { Files.deleteIfExists(temporary); }
    }

    private static String required(Properties properties, String key) throws IOException {
        String value = properties.getProperty(key);
        if (value == null) { throw new IOException("Missing user metadata: " + key); }
        return value;
    }
    private static byte[] decode(Properties properties, String key) throws IOException {
        return Base64.getDecoder().decode(required(properties, key));
    }
    private static String encode(byte[] value) { return Base64.getEncoder().encodeToString(value); }

    @Override
    public void close() throws IOException {
        try { lock.release(); }
        finally { lockChannel.close(); }
    }
}
