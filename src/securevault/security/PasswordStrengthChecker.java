package securevault.security;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import securevault.enums.PasswordStrength;
import securevault.model.Account;
import securevault.model.AccountAnalysis;

public final class PasswordStrengthChecker implements SecurityCheck {
    public PasswordStrength classify(char[] password) {
        boolean lower = false, upper = false, digit = false, symbol = false;
        for (char c : password) {
            if (Character.isLowerCase(c)) { lower = true; }
            else if (Character.isUpperCase(c)) { upper = true; }
            else if (Character.isDigit(c)) { digit = true; }
            else if (!Character.isWhitespace(c)) { symbol = true; }
        }
        int categories = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        if (password.length >= 16 && categories >= 3) { return PasswordStrength.VERY_STRONG; }
        if (password.length >= 12 && categories >= 3) { return PasswordStrength.STRONG; }
        if (password.length >= 8 && categories >= 2) { return PasswordStrength.MODERATE; }
        return PasswordStrength.WEAK;
    }

    @Override
    public void analyze(List<Account> accounts, Map<UUID, AccountAnalysis> results) {
        for (Account account : accounts) {
            char[] password = account.copyPassword();
            try { results.get(account.getId()).setStrength(classify(password)); }
            finally { Arrays.fill(password, '\0'); }
        }
    }
}
