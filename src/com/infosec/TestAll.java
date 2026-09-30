package com.infosec;

import com.infosec.sdes.SDesAlgorithm;

/**
 * 命令行测试：用课程 PPT 参数验证 S-DES 加解密。
 */
public class TestAll {

    public static void main(String[] args) {
        SDesAlgorithm algorithm = new SDesAlgorithm();

        System.out.println("===== S-DES 标准测试 =====");

        // 1. 经典样例（密钥 1010000010，明文 11010111）
        testRoundTrip(algorithm, "11010111", "1010000010");

        // 2. 全零
        testRoundTrip(algorithm, "00000000", "0000000000");

        // 3. 全一
        testRoundTrip(algorithm, "11111111", "1111111111");

        // 4. 交替位
        testRoundTrip(algorithm, "10101010", "1010101010");
    }

    /**
     * 对一组明文和密钥，依次加密、解密，并校验是否还原。
     *
     * @param algorithm S-DES 算法对象
     * @param plainText 明文
     * @param key       密钥
     */
    private static void testRoundTrip(SDesAlgorithm algorithm, String plainText, String key) {
        String cipher = algorithm.encrypt(plainText, key);
        String decrypted = algorithm.decrypt(cipher, key);
        boolean roundTripOk = plainText.equals(decrypted);

        System.out.println("明文=" + plainText
                + " 密钥=" + key
                + " → 密文=" + cipher
                + " → 解密=" + decrypted
                + " 是否还原: " + (roundTripOk ? "✅ true" : "❌ false"));
    }
}