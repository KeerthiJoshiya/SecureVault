package securevault.security;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import securevault.model.Account;
import securevault.model.AccountAnalysis;
import securevault.model.SimilarPasswordMatch;

/** Detects disguised reuse across different platforms without exposing passwords. */
public final class SimilarPasswordChecker implements SecurityCheck {
    private static final int MIN_LENGTH = 8;
    private static final int MIN_BASE_LENGTH = 6;

    @Override
    public void analyze(List<Account> accounts, Map<UUID, AccountAnalysis> results) {
        char[][] passwords = new char[accounts.size()][];
        try {
            for (int i = 0; i < accounts.size(); i++) {
                passwords[i] = accounts.get(i).copyPassword();
            }
            for (int first = 0; first < accounts.size(); first++) {
                for (int second = first + 1; second < accounts.size(); second++) {
                    Account left = accounts.get(first);
                    Account right = accounts.get(second);
                    if (left.getPlatform().equalsIgnoreCase(right.getPlatform())
                            || Arrays.equals(passwords[first], passwords[second])) {
                        continue;
                    }
                    String reason = similarityReason(passwords[first], passwords[second]);
                    if (reason != null) {
                        results.get(left.getId()).addSimilarPassword(new SimilarPasswordMatch(
                                right.getId(), right.getPlatform(), right.getUsername(), reason));
                        results.get(right.getId()).addSimilarPassword(new SimilarPasswordMatch(
                                left.getId(), left.getPlatform(), left.getUsername(), reason));
                    }
                }
            }
        } finally {
            for (char[] password : passwords) {
                if (password != null) { Arrays.fill(password, '\0'); }
            }
        }
    }

    String similarityReason(char[] first, char[] second) {
        if (first.length < MIN_LENGTH || second.length < MIN_LENGTH) { return null; }
        char[] left = lower(first);
        char[] right = lower(second);
        try {
            if (Arrays.equals(left, right)) { return "Differs only by letter case"; }
            if (sameBaseText(left, right)) {
                return "Uses the same base text with a different numeric or symbol ending";
            }
            int allowedChanges = Math.min(left.length, right.length) >= 10 ? 2 : 1;
            if (hasSmallDifference(left, right, allowedChanges)) {
                return allowedChanges == 1 ? "Differs by only one character"
                        : "Differs by only one or two characters";
            }
            return null;
        } finally {
            Arrays.fill(left, '\0');
            Arrays.fill(right, '\0');
        }
    }

    private char[] lower(char[] source) {
        char[] result = source.clone();
        for (int i = 0; i < result.length; i++) { result[i] = Character.toLowerCase(result[i]); }
        return result;
    }

    private int baseEnd(char[] password) {
        int end = password.length;
        while (end > 0 && Character.isDigit(password[end - 1])) { end--; }
        while (end > 0 && !Character.isLetterOrDigit(password[end - 1])) { end--; }
        return end;
    }

    private boolean sameBaseText(char[] first, char[] second) {
        int firstEnd = baseEnd(first);
        int secondEnd = baseEnd(second);
        if (firstEnd < MIN_BASE_LENGTH || firstEnd != secondEnd) { return false; }
        for (int i = 0; i < firstEnd; i++) {
            if (first[i] != second[i]) { return false; }
        }
        return true;
    }

    private boolean hasSmallDifference(char[] first, char[] second, int limit) {
        if (Math.abs(first.length - second.length) > limit) { return false; }
        if (first.length == second.length) {
            int differences = 0;
            for (int i = 0; i < first.length; i++) {
                if (first[i] != second[i] && ++differences > limit) { return false; }
            }
            return differences > 0;
        }
        char[] shorter = first.length < second.length ? first : second;
        char[] longer = first.length < second.length ? second : first;
        int shortIndex = 0;
        int longIndex = 0;
        int skipped = 0;
        while (shortIndex < shorter.length && longIndex < longer.length) {
            if (shorter[shortIndex] == longer[longIndex]) {
                shortIndex++;
                longIndex++;
            } else {
                longIndex++;
                if (++skipped > limit) { return false; }
            }
        }
        skipped += longer.length - longIndex;
        return shortIndex == shorter.length && skipped > 0 && skipped <= limit;
    }
}
