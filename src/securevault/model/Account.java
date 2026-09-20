package securevault.model;

import java.util.Arrays;
import java.util.UUID;
import securevault.enums.AccountType;
import securevault.exception.ValidationException;

/** An online account; passwords must never be included in display output. */
public final class Account {
    private final UUID id;
    private final String platform;
    private final String username;
    private final AccountType type;
    private final char[] password;

    public Account(UUID id, String platform, String username, AccountType type,
                   char[] password) throws ValidationException {
        if (id == null || type == null) {
            throw new ValidationException("Account ID and category are required.");
        }
        this.platform = validateText(platform, "Platform");
        this.username = validateText(username, "Username/email");
        if (password == null || password.length == 0 || password.length > 1024) {
            throw new ValidationException("Account password must contain 1 to 1024 characters.");
        }
        this.id = id;
        this.type = type;
        this.password = password.clone();
    }

    private static String validateText(String value, String label) throws ValidationException {
        if (value == null || value.isBlank() || value.strip().length() > 120
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new ValidationException(label + " must contain 1 to 120 printable characters.");
        }
        return value.strip();
    }

    public UUID getId() { return id; }
    public String getPlatform() { return platform; }
    public String getUsername() { return username; }
    public AccountType getType() { return type; }
    public char[] copyPassword() { return password.clone(); }

    public void clearPassword() {
        Arrays.fill(password, '\0');
    }

    @Override
    public String toString() {
        return platform + " | " + username + " | " + type;
    }
}
