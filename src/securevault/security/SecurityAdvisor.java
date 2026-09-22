package securevault.security;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import securevault.enums.PasswordStrength;
import securevault.model.AccountAnalysis;
import securevault.model.RecommendationGroup;

public final class SecurityAdvisor {
    public List<RecommendationGroup> recommend(List<AccountAnalysis> results) {
        List<RecommendationGroup> groups = new ArrayList<>();
        for (AccountAnalysis result : results) {
            Set<String> advice = new LinkedHashSet<>();
            if (result.getStrength() == PasswordStrength.WEAK || result.getStrength() == PasswordStrength.MODERATE) {
                advice.add("Choose a longer, unique password; aim for at least 16 characters.");
            }
            if (result.getReuseCount() > 1) {
                advice.add("Replace the password reused across " + result.getReuseCount() + " accounts.");
            }
            result.getSimilarPasswords().forEach(match -> advice.add(
                    "Use a completely unrelated password; it is similar to " + match.otherPlatform()
                    + " (" + match.reason().toLowerCase(java.util.Locale.ROOT) + ")."));
            for (String pattern : result.getPatterns()) {
                advice.add("Remove this predictable feature: "
                        + pattern.toLowerCase(java.util.Locale.ROOT) + ".");
            }
            if (advice.isEmpty()) {
                advice.add("No issues detected by current checks. Keep this password unique and enable MFA where available.");
            }
            groups.add(new RecommendationGroup(result.getAccountId(), result.getPlatform(),
                    result.getUsername(), result.getRisk(), result.getScore(), new ArrayList<>(advice)));
        }
        groups.sort(Comparator.comparingInt((RecommendationGroup group) -> riskPriority(group.getRisk()))
                .thenComparing(RecommendationGroup::getPlatform, String.CASE_INSENSITIVE_ORDER));
        return groups;
    }

    private int riskPriority(securevault.enums.RiskLevel risk) {
        return switch (risk) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
        };
    }
}
