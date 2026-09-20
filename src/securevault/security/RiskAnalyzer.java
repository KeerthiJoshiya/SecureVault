package securevault.security;

import securevault.enums.RiskLevel;
import securevault.model.AccountAnalysis;

public final class RiskAnalyzer {
    public void calculate(AccountAnalysis result) {
        int score = result.getStrength().getBaseScore();
        if (result.getReuseCount() > 1) { score -= 30; }
        if (!result.getPatterns().isEmpty()) { score -= 20; }
        score = Math.max(0, score);
        RiskLevel risk = score < 25 ? RiskLevel.CRITICAL
                : score < 50 ? RiskLevel.HIGH
                : score < 75 ? RiskLevel.MEDIUM : RiskLevel.LOW;
        result.setRiskAndScore(risk, score);
    }
}
