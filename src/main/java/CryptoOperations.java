import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class CryptoOperations {

    // ==========================================
    // 1. SYMMETRIC ENCRYPTION (AES, DES, 3DES)
    // ==========================================
    
    // Helper method to safely size the user's text key for the chosen algorithm
    private static SecretKeySpec generateKeySpec(String key, String algorithm) throws Exception {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        keyBytes = sha.digest(keyBytes); // Hash the key to get a consistent byte length
        
        if (algorithm.equals("AES")) {
            keyBytes = Arrays.copyOf(keyBytes, 16); // AES needs 16 bytes
        } else if (algorithm.equals("DES")) {
            keyBytes = Arrays.copyOf(keyBytes, 8);  // DES needs 8 bytes
        } else if (algorithm.equals("DESede")) { // 3DES in Java is "DESede"
            keyBytes = Arrays.copyOf(keyBytes, 24); // 3DES needs 24 bytes
        }
        return new SecretKeySpec(keyBytes, algorithm);
    }

    public static String encryptSymmetric(String algo, String text, String key) throws Exception {
        if (algo.equals("3DES")) algo = "DESede"; // Java naming convention
        SecretKeySpec secretKey = generateKeySpec(key, algo);
        Cipher cipher = Cipher.getInstance(algo);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptSymmetric(String algo, String encryptedBase64, String key) throws Exception {
        if (algo.equals("3DES")) algo = "DESede";
        SecretKeySpec secretKey = generateKeySpec(key, algo);
        Cipher cipher = Cipher.getInstance(algo);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedBase64);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // ==========================================
    // 2. ASYMMETRIC ENCRYPTION (RSA)
    // ==========================================
    
    // Storing the keypair in memory for the session to make testing easy
    private static KeyPair rsaKeyPair;

    public static String generateRSAKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rsaKeyPair = generator.generateKeyPair();
        return "RSA Keys Generated Successfully!\nPublic Key: " + 
               Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()).substring(0, 50) + "...";
    }

    public static String encryptRSA(String text) throws Exception {
        if (rsaKeyPair == null) generateRSAKeys(); // Auto-generate if missing
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptRSA(String encryptedBase64) throws Exception {
        if (rsaKeyPair == null) return "Error: No RSA Keys generated yet.";
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedBase64);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // ==========================================
    // 3. ENCODING & DECODING
    // ==========================================
    
    public static String encode(String type, String text) throws Exception {
        if (type.equals("Base64")) {
            return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
        } else if (type.equals("Hex")) {
            StringBuilder hexString = new StringBuilder();
            for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
                hexString.append(String.format("%02X ", b));
            }
            return hexString.toString().trim();
        } else if (type.equals("URL")) {
            return URLEncoder.encode(text, StandardCharsets.UTF_8.toString());
        }
        return "Unknown Encoding";
    }

    public static String decode(String type, String text) throws Exception {
        if (type.equals("Base64")) {
            return new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
        } else if (type.equals("Hex")) {
            // Very basic Hex decoder
            text = text.replace(" ", "");
            byte[] bytes = new byte[text.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
            }
            return new String(bytes, StandardCharsets.UTF_8);
        } else if (type.equals("URL")) {
            return URLDecoder.decode(text, StandardCharsets.UTF_8.toString());
        }
        return "Unknown Decoding";
    }

    // ==========================================
    // 4. HASHING (SHA-256, SHA-512, Salted)
    // ==========================================
    
    public static String hashText(String algo, String text, String salt) throws Exception {
        String hashAlgo = algo.equals("SaltedHash") ? "SHA-256" : algo; // Default salted to SHA-256
        MessageDigest digest = MessageDigest.getInstance(hashAlgo);
        
        if (salt != null && !salt.isEmpty()) {
            digest.update(salt.getBytes(StandardCharsets.UTF_8));
        }
        
        byte[] hashBytes = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}