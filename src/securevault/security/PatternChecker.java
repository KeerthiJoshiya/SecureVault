package securevault.security;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import securevault.model.Account;
import securevault.model.AccountAnalysis;

public final class PatternChecker implements SecurityCheck {
    private static final List<String> COMMON_WORDS = List.of("password", "welcome", "letmein", "admin");
    private static final List<String> KEYBOARD_ROWS = List.of("qwertyuiop", "asdfghjkl", "zxcvbnm");

    @Override
    public void analyze(List<Account> accounts, Map<UUID, AccountAnalysis> results) {
        for (Account account : accounts) {
            char[] password = account.copyPassword();
            try {
                for (int i = 0; i < password.length; i++) { password[i] = Character.toLowerCase(password[i]); }
                AccountAnalysis result = results.get(account.getId());
                if (COMMON_WORDS.stream().anyMatch(word -> contains(password, word))) {
                    result.addPattern("Contains a common password word");
                }
                String username = account.getUsername().toLowerCase(Locale.ROOT).split("@", 2)[0];
                if (username.length() >= 3 && contains(password, username)) {
                    result.addPattern("Contains the username/email name");
                }
                for (int i = 0; i + 2 < password.length; i++) {
                    char a = password[i], b = password[i + 1], c = password[i + 2];
                    if (a == b && b == c) { result.addPattern("Repeats a character three or more times"); }
                    if (isAsciiDigit(a) && isAsciiDigit(b) && isAsciiDigit(c)
                            && ((b == a + 1 && c == b + 1) || (b == a - 1 && c == b - 1))) {
                        result.addPattern("Contains ascending/descending sequential digits");
                    }
                }
                for (String row : KEYBOARD_ROWS) {
                    String reversed = new StringBuilder(row).reverse().toString();
                    for (int i = 0; i + 2 < row.length(); i++) {
                        if (contains(password, row.substring(i, i + 3))
                                || contains(password, reversed.substring(i, i + 3))) {
                            result.addPattern("Contains a predictable keyboard sequence");
                        }
                    }
                }
                for (int i = 0; i + 3 < password.length; i++) {
                    if (((password[i] == '1' && password[i + 1] == '9')
                            || (password[i] == '2' && password[i + 1] == '0'))
                            && isAsciiDigit(password[i + 2]) && isAsciiDigit(password[i + 3])) {
                        result.addPattern("Contains a year-like number (1900-2099)");
                    }
                }
            } finally { Arrays.fill(password, '\0'); }
        }
    }

    private static boolean isAsciiDigit(char c) { return c >= '0' && c <= '9'; }

    private static boolean contains(char[] password, String fragment) {
        for (int i = 0; i <= password.length - fragment.length(); i++) {
            int j = 0;
            while (j < fragment.length() && password[i + j] == fragment.charAt(j)) { j++; }
            if (j == fragment.length()) { return true; }
        }
        return false;
    }
}
