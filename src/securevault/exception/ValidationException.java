package securevault.exception;

/** A recoverable mistake in user-supplied information. */
public class ValidationException extends Exception {
    public ValidationException(String message) {
        super(message);
    }
}
