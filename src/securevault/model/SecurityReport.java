package securevault.model;

import java.time.Instant;
import java.util.List;
import securevault.enums.PasswordStrength;
import securevault.enums.RiskLevel;

public final class SecurityReport {
    private final List<AccountAnalysis> analyses;
    private final List<String> recommendations;
    private final Instant generatedAt;
    private final int score;

    public SecurityReport(List<AccountAnalysis> analyses, List<String> recommendations) {
        this.analyses = List.copyOf(analyses);
        this.recommendations = List.copyOf(recommendations);
        generatedAt = Instant.now();
        score = (int) Math.round(analyses.stream().mapToInt(AccountAnalysis::getScore).average().orElse(0));
    }

    public List<AccountAnalysis> getAnalyses() { return analyses; }
    public List<String> getRecommendations() { return recommendations; }
    public Instant getGeneratedAt() { return generatedAt; }
    public int getScore() { return score; }
    public long countStrength(PasswordStrength strength) {
        return analyses.stream().filter(a -> a.getStrength() == strength).count();
    }
    public long getReusedAccountCount() {
        return analyses.stream().filter(a -> a.getReuseCount() > 1).count();
    }
    public long getPatternAccountCount() {
        return analyses.stream().filter(a -> !a.getPatterns().isEmpty()).count();
    }
    public long getSimilarPasswordAccountCount() {
        return analyses.stream().filter(a -> !a.getSimilarPasswords().isEmpty()).count();
    }
    public long getHighRiskCount() {
        return analyses.stream().filter(a -> a.getRisk() == RiskLevel.HIGH
                || a.getRisk() == RiskLevel.CRITICAL).count();
    }
}
