package securevault.security;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PasswordHasher {
    public static final int ITERATIONS = 600_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    public byte[] newSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /** Also used with an independent salt to derive the vault encryption key. */
    public byte[] derive(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, ITERATIONS, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
        } finally { specification.clearPassword(); }
    }

    public boolean verify(char[] password, byte[] salt, byte[] expected) throws GeneralSecurityException {
        byte[] actual = derive(password, salt);
        try { return MessageDigest.isEqual(actual, expected); }
        finally { Arrays.fill(actual, (byte) 0); }
    }
}
