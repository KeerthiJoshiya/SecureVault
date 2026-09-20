package securevault.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import securevault.enums.AccountType;
import securevault.exception.ValidationException;
import securevault.model.Account;
import securevault.model.User;
import securevault.persistence.FileStore;

/** A logged-in session owns one user's decrypted accounts and key. */
public final class AccountService implements AutoCloseable {
    private final User user;
    private final FileStore store;
    private final byte[] key;
    private final List<Account> accounts;
    private boolean closed;

    public AccountService(User user, byte[] key, FileStore store) throws IOException, GeneralSecurityException {
        this.user = user;
        this.store = store;
        this.accounts = store.loadAccounts(user, key);
        this.key = key.clone();
    }

    public String getUsername() { return user.getUsername(); }
    public List<Account> list() { ensureOpen(); return List.copyOf(accounts); }

    public List<Account> search(String query) {
        ensureOpen();
        String needle = query.strip().toLowerCase(Locale.ROOT);
        return accounts.stream().filter(account -> account.getPlatform().toLowerCase(Locale.ROOT).contains(needle)
                || account.getUsername().toLowerCase(Locale.ROOT).contains(needle)
                || account.getType().name().toLowerCase(Locale.ROOT).contains(needle)).toList();
    }

    public void add(String platform, String username, AccountType type, char[] password)
            throws ValidationException, IOException, GeneralSecurityException {
        ensureOpen();
        if (accounts.size() >= FileStore.MAX_ACCOUNTS) { throw new ValidationException("Maximum 500 accounts per user."); }
        Account account = new Account(UUID.randomUUID(), platform, username, type, password);
        boolean saved = false;
        try {
            ensureUnique(account, null);
            List<Account> updated = new ArrayList<>(accounts);
            updated.add(account);
            store.saveAccounts(user, key, updated);
            accounts.add(account);
            saved = true;
        } finally { if (!saved) { account.clearPassword(); } }
    }

    public void update(UUID id, String platform, String username, AccountType type, char[] password)
            throws ValidationException, IOException, GeneralSecurityException {
        ensureOpen();
        int index = find(id);
        Account replacement = new Account(id, platform, username, type, password);
        boolean saved = false;
        try {
            ensureUnique(replacement, id);
            List<Account> updated = new ArrayList<>(accounts);
            updated.set(index, replacement);
            store.saveAccounts(user, key, updated);
            accounts.set(index, replacement).clearPassword();
            saved = true;
        } finally { if (!saved) { replacement.clearPassword(); } }
    }

    public void delete(UUID id) throws ValidationException, IOException, GeneralSecurityException {
        ensureOpen();
        int index = find(id);
        List<Account> updated = new ArrayList<>(accounts);
        updated.remove(index);
        store.saveAccounts(user, key, updated);
        accounts.remove(index).clearPassword();
    }

    private void ensureUnique(Account candidate, UUID excluded) throws ValidationException {
        for (Account existing : accounts) {
            if (!existing.getId().equals(excluded)
                    && existing.getPlatform().equalsIgnoreCase(candidate.getPlatform())
                    && existing.getUsername().equalsIgnoreCase(candidate.getUsername())) {
                throw new ValidationException("That platform and username already exist. Update the existing account.");
            }
        }
    }

    private int find(UUID id) throws ValidationException {
        for (int i = 0; i < accounts.size(); i++) {
            if (accounts.get(i).getId().equals(id)) { return i; }
        }
        throw new ValidationException("Account not found.");
    }

    private void ensureOpen() {
        if (closed) { throw new IllegalStateException("Session has been closed."); }
    }

    @Override
    public void close() {
        if (!closed) {
            accounts.forEach(Account::clearPassword);
            accounts.clear();
            Arrays.fill(key, (byte) 0);
            closed = true;
        }
    }
}
