package securevault.security;

import securevault.enums.RiskLevel;
import securevault.model.AccountAnalysis;

public final class RiskAnalyzer {
    public void calculate(AccountAnalysis result) {
        int score = result.getStrength().getBaseScore();
        int reusePenalty = result.getReuseCount() >= 3 ? 35 : result.getReuseCount() == 2 ? 25 : 0;
        int patternPenalty = Math.min(20, result.getPatterns().size() * 10);
        score -= reusePenalty + patternPenalty;
        score = Math.max(0, score);
        RiskLevel risk = score < 25 ? RiskLevel.CRITICAL
                : score < 50 ? RiskLevel.HIGH
                : score < 80 ? RiskLevel.MEDIUM : RiskLevel.LOW;
        result.setRiskAndScore(risk, score, reusePenalty, patternPenalty);
    }
}
