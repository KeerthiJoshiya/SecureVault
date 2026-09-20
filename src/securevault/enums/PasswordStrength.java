package securevault.enums;

public enum PasswordStrength {
    WEAK(20), MODERATE(50), STRONG(80), VERY_STRONG(100);

    private final int baseScore;

    PasswordStrength(int baseScore) { this.baseScore = baseScore; }
    public int getBaseScore() { return baseScore; }
}
