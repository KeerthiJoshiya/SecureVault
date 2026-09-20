package securevault.enums;

public enum PasswordStrength {
    WEAK(25), MODERATE(60), STRONG(80), VERY_STRONG(100);

    private final int baseScore;

    PasswordStrength(int baseScore) { this.baseScore = baseScore; }
    public int getBaseScore() { return baseScore; }
}
