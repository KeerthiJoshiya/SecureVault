package securevault.security;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Versioned authenticated encryption; a fresh nonce is generated for each save. */
public final class VaultEncryption {
    private static final int MAGIC = 0x53563101;
    private static final int NONCE_SIZE = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    public byte[] encrypt(byte[] plaintext, byte[] key, UUID owner) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        Cipher cipher = cipher(Cipher.ENCRYPT_MODE, key, nonce, owner);
        byte[] encrypted = cipher.doFinal(plaintext);
        return ByteBuffer.allocate(4 + NONCE_SIZE + encrypted.length)
                .putInt(MAGIC).put(nonce).put(encrypted).array();
    }

    public byte[] decrypt(byte[] stored, byte[] key, UUID owner) throws GeneralSecurityException {
        if (stored.length < 4 + NONCE_SIZE + 16) {
            throw new GeneralSecurityException("Vault file is incomplete.");
        }
        ByteBuffer buffer = ByteBuffer.wrap(stored);
        if (buffer.getInt() != MAGIC) { throw new GeneralSecurityException("Unsupported vault format."); }
        byte[] nonce = new byte[NONCE_SIZE];
        buffer.get(nonce);
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);
        return cipher(Cipher.DECRYPT_MODE, key, nonce, owner).doFinal(encrypted);
    }

    private Cipher cipher(int mode, byte[] key, byte[] nonce, UUID owner) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(("SecureVault-v1:" + owner).getBytes(StandardCharsets.UTF_8));
        return cipher;
    }
}
