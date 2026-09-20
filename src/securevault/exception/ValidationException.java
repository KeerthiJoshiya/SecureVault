package securevault.exception;

/** A recoverable mistake in user-supplied information. */
public class ValidationException extends Exception {
    private static final long serialVersionUID = 1L;

    public ValidationException(String message) {
        super(message);
    }
}
