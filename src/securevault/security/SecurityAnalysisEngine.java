package securevault.security;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import securevault.model.Account;
import securevault.model.AccountAnalysis;
import securevault.model.SecurityReport;

public final class SecurityAnalysisEngine {
    private final List<SecurityCheck> checks = List.of(new PasswordStrengthChecker(),
            new DuplicatePasswordChecker(), new PatternChecker());

    public SecurityReport analyze(List<Account> accounts) {
        Map<UUID, AccountAnalysis> results = new LinkedHashMap<>();
        for (Account account : accounts) { results.put(account.getId(), new AccountAnalysis(account)); }
        for (SecurityCheck check : checks) { check.analyze(accounts, results); }
        RiskAnalyzer riskAnalyzer = new RiskAnalyzer();
        results.values().forEach(riskAnalyzer::calculate);
        List<AccountAnalysis> analyses = new ArrayList<>(results.values());
        return new SecurityReport(analyses, new SecurityAdvisor().recommend(analyses));
    }
}
