package securevault.model;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import securevault.enums.PasswordStrength;
import securevault.enums.RiskLevel;

/** Report data contains findings, never passwords. */
public final class AccountAnalysis {
    private final UUID accountId;
    private final String platform;
    private final String username;
    private PasswordStrength strength = PasswordStrength.WEAK;
    private int reuseCount = 1;
    private final Set<String> patterns = new LinkedHashSet<>();
    private int score;
    private RiskLevel risk = RiskLevel.CRITICAL;

    public AccountAnalysis(Account account) {
        accountId = account.getId();
        platform = account.getPlatform();
        username = account.getUsername();
    }

    public UUID getAccountId() { return accountId; }
    public String getPlatform() { return platform; }
    public String getUsername() { return username; }
    public PasswordStrength getStrength() { return strength; }
    public int getReuseCount() { return reuseCount; }
    public Set<String> getPatterns() { return java.util.Collections.unmodifiableSet(patterns); }
    public int getScore() { return score; }
    public RiskLevel getRisk() { return risk; }
    public void setStrength(PasswordStrength strength) { this.strength = strength; }
    public void setReuseCount(int count) { reuseCount = count; }
    public void addPattern(String reason) { patterns.add(reason); }
    public void setRiskAndScore(RiskLevel risk, int score) {
        this.risk = risk;
        this.score = score;
    }
}
