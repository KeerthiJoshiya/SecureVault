package securevault.model;

import java.util.Objects;
import java.util.UUID;

/** Immutable description of a similar-password relationship; stores no password. */
public record SimilarPasswordMatch(UUID otherAccountId, String otherPlatform,
                                   String otherUsername, String reason) {
    public SimilarPasswordMatch {
        Objects.requireNonNull(otherAccountId, "otherAccountId");
        Objects.requireNonNull(otherPlatform, "otherPlatform");
        Objects.requireNonNull(otherUsername, "otherUsername");
        Objects.requireNonNull(reason, "reason");
    }
}
