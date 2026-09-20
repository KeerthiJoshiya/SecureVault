package securevault;

import java.util.UUID;
import java.util.List;
import securevault.enums.AccountType;
import securevault.enums.PasswordStrength;
import securevault.enums.RiskLevel;
import securevault.exception.ValidationException;
import securevault.model.Account;
import securevault.model.SecurityReport;
import securevault.security.PasswordStrengthChecker;
import securevault.security.SecurityAnalysisEngine;

/** Small executable checks; assertions remain active without the -ea option. */
public final class TestRunner {
    private static int checks;

    public static void main(String[] args) throws Exception {
        char[] input = "Example@123".toCharArray();
        Account account = new Account(UUID.randomUUID(), " Mail ", "student", AccountType.EMAIL, input);
        input[0] = 'X';
        check(account.copyPassword()[0] == 'E', "Constructor must copy passwords");
        char[] copy = account.copyPassword();
        copy[0] = 'X';
        check(account.copyPassword()[0] == 'E', "Getter must copy passwords");
        check(account.getPlatform().equals("Mail"), "Platform should be trimmed");
        check(!account.toString().contains("Example@123"), "Display must omit passwords");
        try {
            new Account(UUID.randomUUID(), " ", "student", AccountType.EMAIL, input);
            throw new AssertionError("Blank platform accepted");
        } catch (ValidationException expected) {
            checks++;
        }
        analysisChecks();
        System.out.println("PASS: " + checks + " checks");
    }

    private static void analysisChecks() throws Exception {
        PasswordStrengthChecker strength = new PasswordStrengthChecker();
        check(strength.classify("abc".toCharArray()) == PasswordStrength.WEAK, "Short passwords are weak");
        check(strength.classify("Abcdefg2".toCharArray()) == PasswordStrength.MODERATE, "Eight-character boundary");
        check(strength.classify("Abcdefghijk2".toCharArray()) == PasswordStrength.STRONG, "Twelve-character boundary");
        check(strength.classify("V9!mR2$kL7&zP4@x".toCharArray()) == PasswordStrength.VERY_STRONG, "Sixteen-character boundary");
        Account first = account("Mail", "student", "Welcome@123");
        Account second = account("Social", "student", "Welcome@123");
        SecurityAnalysisEngine engine = new SecurityAnalysisEngine();
        SecurityReport report = engine.analyze(List.of(first, second));
        check(report.getReusedAccountCount() == 2, "Both reused accounts are counted");
        check(report.getAnalyses().get(0).getReuseCount() == 2, "Reuse includes this account");
        check(report.getScore() == 0, "Example score is calculated correctly");
        check(report.getHighRiskCount() == 2, "Critical accounts count as high-risk");
        check(report.getAnalyses().get(0).getRisk() == RiskLevel.CRITICAL, "Critical risk threshold");
        check(report.getAnalyses().get(0).getPatterns().size() == 2, "Common word and sequence detected");
        check(!report.getRecommendations().isEmpty(), "Findings create advice");
        SecurityReport empty = engine.analyze(List.of());
        check(empty.getAnalyses().isEmpty() && empty.getRecommendations().isEmpty(), "Empty vault has no findings");
        // These strings have the same Arrays.hashCode(char[]) but are not equal.
        report = engine.analyze(List.of(account("A", "student", "Aa"), account("B", "student", "BB")));
        check(report.getReusedAccountCount() == 0, "Hash collision must not cause false reuse");
        report = engine.analyze(List.of(account("Mail", "Keerthi@example.com", "KEERTHI!987aaa2026qwe")));
        check(report.getAnalyses().get(0).getPatterns().size() == 5, "Username, reverse digits, repeats, year, keyboard");
        report = engine.analyze(List.of(account("Work", "student", "V9!mR2$kL7&zP4@x")));
        check(report.getScore() == 100 && report.getHighRiskCount() == 0, "Clean unique password score");
    }

    private static Account account(String platform, String username, String password) throws Exception {
        return new Account(UUID.randomUUID(), platform, username, AccountType.OTHER, password.toCharArray());
    }

    private static void check(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
        checks++;
    }
}
