package securevault.security;

import java.util.ArrayList;
import java.util.List;
import securevault.enums.PasswordStrength;
import securevault.model.AccountAnalysis;

public final class SecurityAdvisor {
    public List<String> recommend(List<AccountAnalysis> results) {
        List<String> advice = new ArrayList<>();
        for (AccountAnalysis result : results) {
            String label = result.getPlatform() + " (" + result.getUsername() + "): ";
            if (result.getStrength() == PasswordStrength.WEAK || result.getStrength() == PasswordStrength.MODERATE) {
                advice.add(label + "choose a longer, unique password; aim for at least 16 characters.");
            }
            if (result.getReuseCount() > 1) {
                advice.add(label + "replace the password reused across " + result.getReuseCount() + " accounts.");
            }
            result.getSimilarPasswords().forEach(match -> advice.add(label
                    + "use a completely unrelated password; it is similar to "
                    + match.otherPlatform() + " (" + match.reason().toLowerCase(java.util.Locale.ROOT) + ")."));
            for (String pattern : result.getPatterns()) {
                advice.add(label + "remove this predictable feature: " + pattern.toLowerCase(java.util.Locale.ROOT) + ".");
            }
        }
        if (!results.isEmpty() && advice.isEmpty()) {
            advice.add("No issues detected by these checks. Keep passwords unique and enable MFA where available.");
        }
        return advice;
    }
}
