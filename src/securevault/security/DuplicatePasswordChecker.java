package securevault.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import securevault.model.Account;
import securevault.model.AccountAnalysis;

/** Hash buckets accelerate lookup; exact comparison handles hash collisions. */
public final class DuplicatePasswordChecker implements SecurityCheck {
    @Override
    public void analyze(List<Account> accounts, Map<UUID, AccountAnalysis> results) {
        Map<Integer, List<Account>> buckets = new HashMap<>();
        for (Account account : accounts) {
            char[] password = account.copyPassword();
            try {
                buckets.computeIfAbsent(Arrays.hashCode(password), key -> new ArrayList<>()).add(account);
            } finally { Arrays.fill(password, '\0'); }
        }
        for (List<Account> bucket : buckets.values()) {
            for (Account account : bucket) {
                char[] password = account.copyPassword();
                try {
                    int matches = 0;
                    for (Account candidate : bucket) {
                        char[] other = candidate.copyPassword();
                        try { if (Arrays.equals(password, other)) { matches++; } }
                        finally { Arrays.fill(other, '\0'); }
                    }
                    results.get(account.getId()).setReuseCount(matches);
                } finally { Arrays.fill(password, '\0'); }
            }
        }
    }
}
