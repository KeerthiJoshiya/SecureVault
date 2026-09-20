package securevault.security;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import securevault.model.Account;
import securevault.model.AccountAnalysis;

/** Every check sees the whole collection so cross-account checks are possible. */
public interface SecurityCheck {
    void analyze(List<Account> accounts, Map<UUID, AccountAnalysis> results);
}
