package com.infosec.sdes;

import java.nio.charset.StandardCharsets;

/**
 * 关卡3：把字符串按字节用 S-DES 加密/解密。
 */
public class SDesStringCodec {

    private final SDesAlgorithm algorithm = new SDesAlgorithm();

    /**
     * 加密字符串，每个字节独立用 S-DES 加密。
     */
    public String encryptString(String plainText, String key) {
        byte[] bytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = new byte[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            String binary = toBinaryString(bytes[i]);
            String cipherBinary = algorithm.encrypt(binary, key);
            encrypted[i] = (byte) Integer.parseInt(cipherBinary, 2);
        }
        return new String(encrypted, StandardCharsets.ISO_8859_1);
    }

    /**
     * 解密字符串，每个字节独立用 S-DES 解密。
     */
    public String decryptString(String cipherText, String key) {
        byte[] bytes = cipherText.getBytes(StandardCharsets.ISO_8859_1);
        byte[] decrypted = new byte[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            String binary = toBinaryString(bytes[i]);
            String plainBinary = algorithm.decrypt(binary, key);
            decrypted[i] = (byte) Integer.parseInt(plainBinary, 2);
        }
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * 字节 → 8 位二进制字符串。
     */
    private String toBinaryString(byte value) {
        return String.format("%8s", Integer.toBinaryString(value & 0xFF)).replace(' ', '0');
    }
}