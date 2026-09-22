package securevault.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import securevault.enums.RiskLevel;

/** Recommendations belonging to one account, ready for presentation in any UI. */
public final class RecommendationGroup {
    private final UUID accountId;
    private final String platform;
    private final String username;
    private final RiskLevel risk;
    private final int score;
    private final List<String> recommendations;

    public RecommendationGroup(UUID accountId, String platform, String username,
                               RiskLevel risk, int score, List<String> recommendations) {
        this.accountId = Objects.requireNonNull(accountId);
        this.platform = Objects.requireNonNull(platform);
        this.username = Objects.requireNonNull(username);
        this.risk = Objects.requireNonNull(risk);
        this.score = score;
        this.recommendations = List.copyOf(recommendations);
    }

    public UUID getAccountId() { return accountId; }
    public String getPlatform() { return platform; }
    public String getUsername() { return username; }
    public RiskLevel getRisk() { return risk; }
    public int getScore() { return score; }
    public List<String> getRecommendations() { return recommendations; }
}
