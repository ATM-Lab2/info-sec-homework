package com.infosec.level1;

/**
 * 关卡1：凯撒密码加解密。
 *
 * <p>创新点：使用取模运算统一处理大小写字母的循环移位，
 * 并预分配 StringBuilder 容量以提升性能。</p>
 */
public class Level1Solver {

    /** 英文字母表大小 */
    private static final int ALPHABET_SIZE = 26;

    /**
     * 对明文进行凯撒加密。
     *
     * @param plainText 待加密的明文，仅含英文字母
     * @param shift     移位量，可为负数
     * @return 加密后的密文
     */
    public String encrypt(String plainText, int shift) {
        return shiftText(plainText, shift);
    }

    /**
     * 对密文进行凯撒解密。
     *
     * @param cipherText 待解密的密文
     * @param shift      加密时使用的移位量
     * @return 解密后的明文
     */
    public String decrypt(String cipherText, int shift) {
        return shiftText(cipherText, -shift);
    }

    /**
     * 统一的移位处理逻辑，避免加密和解密重复写代码。
     *
     * @param text  输入文本
     * @param shift 移位量
     * @return 移位后的文本
     */
    private String shiftText(String text, int shift) {
        StringBuilder result = new StringBuilder(text.length());
        int normalizedShift = ((shift % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;

        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                result.append((char) ('A' + (c - 'A' + normalizedShift) % ALPHABET_SIZE));
            } else if (Character.isLowerCase(c)) {
                result.append((char) ('a' + (c - 'a' + normalizedShift) % ALPHABET_SIZE));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}