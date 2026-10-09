package Utils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class AsyncEncryption {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsyncEncryption() {}

    public AsyncEncryption(String base64PublicKey, String base64PrivateKey) {
        if (base64PublicKey != null && !base64PublicKey.isEmpty()) {
            this.publicKey = getPublicKeyFromBase64(base64PublicKey);
        }
        if (base64PrivateKey != null && !base64PrivateKey.isEmpty()) {
            this.privateKey = getPrivateKeyFromBase64(base64PrivateKey);
        }
    }

    // =========================================================
    // 1) Generates Private and Public Keys and Returns Them
    // =========================================================
    public Map<String, String> generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(KEY_SIZE);
            KeyPair pair = keyGen.generateKeyPair();

            this.publicKey = pair.getPublic();
            this.privateKey = pair.getPrivate();

            Map<String, String> keysMap = new HashMap<>();
            keysMap.put("publicKey", Base64.getEncoder().encodeToString(this.publicKey.getEncoded()));
            keysMap.put("privateKey", Base64.getEncoder().encodeToString(this.privateKey.getEncoded()));
            return keysMap;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 2) Encrypts String Data (Using Public Key)
    // =========================================================
    public String encrypt(String plainText) {
        if (this.publicKey == null) {
            throw new IllegalStateException("Public key is not initialized for encryption.");
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
            byte[] cipherBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(cipherBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt data: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 3) Decrypts String Data (Using Private Key)
    // =========================================================
    public String decrypt(String encryptedText) {
        if (this.privateKey == null) {
            throw new IllegalStateException("Private key is not initialized for decryption.");
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt data: " + e.getMessage(), e);
        }
    }

    // =========================================================
    // 4) Get Keys Functions
    // =========================================================
    public String getPublicKeyAsBase64() {
        if (this.publicKey == null) return null;
        return Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
    }

    public String getPrivateKeyAsBase64() {
        if (this.privateKey == null) return null;
        return Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public void setPublicKey(String base64PublicKey) {
        this.publicKey = getPublicKeyFromBase64(base64PublicKey);
    }

    public void setPrivateKey(String base64PrivateKey) {
        this.privateKey = getPrivateKeyFromBase64(base64PrivateKey);
    }

    private PublicKey getPublicKeyFromBase64(String base64Key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Invalid Base64 Public Key: " + e.getMessage(), e);
        }
    }

    private PrivateKey getPrivateKeyFromBase64(String base64Key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Invalid Base64 Private Key: " + e.getMessage(), e);
        }
    }
}