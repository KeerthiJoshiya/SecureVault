package securevault;

import java.util.UUID;
import securevault.enums.AccountType;
import securevault.exception.ValidationException;
import securevault.model.Account;

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
        System.out.println("PASS: " + checks + " checks");
    }

    private static void check(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
        checks++;
    }
}
