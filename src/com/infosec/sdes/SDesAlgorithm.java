package com.infosec.sdes;

/**
 * S-DES 算法的核心实现：密钥扩展、加密、解密。
 *
 * <p>密钥和明文均使用二进制字符串（如 "10101010"）表示。</p>
 */
public class SDesAlgorithm {

    /**
     * 对 8 位明文进行 S-DES 加密。
     *
     * @param plainText 8 位二进制明文
     * @param key       10 位二进制密钥
     * @return 8 位二进制密文
     */
    public String encrypt(String plainText, String key) {
        validateBinary(plainText, 8, "明文");
        validateBinary(key, 10, "密钥");

        String[] subKeys = generateSubKeys(key);
        return process(plainText, subKeys[0], subKeys[1]);
    }

    /**
     * 对 8 位密文进行 S-DES 解密。
     *
     * @param cipherText 8 位二进制密文
     * @param key        10 位二进制密钥
     * @return 8 位二进制明文
     */
    public String decrypt(String cipherText, String key) {
        validateBinary(cipherText, 8, "密文");
        validateBinary(key, 10, "密钥");

        String[] subKeys = generateSubKeys(key);
        // 解密：两轮子密钥交换使用顺序
        return process(cipherText, subKeys[1], subKeys[0]);
    }

    /**
     * 由 10 位主密钥生成子密钥 K1、K2。
     *
     * @param key 10 位密钥
     * @return [K1, K2]
     */
    public String[] generateSubKeys(String key) {
        // P10 置换
        String permutedKey = permute(key, SDesConstants.P10);

        // 分成左右各 5 位
        String leftHalf = permutedKey.substring(0, 5);
        String rightHalf = permutedKey.substring(5);

        // LS-1：左移 1 位，再经 P8 得到 K1
        String leftShift1 = leftShift(leftHalf, 1);
        String rightShift1 = leftShift(rightHalf, 1);
        String key1 = permute(leftShift1 + rightShift1, SDesConstants.P8);

        // LS-2：再左移 2 位，再经 P8 得到 K2
        String leftShift2 = leftShift(leftShift1, 2);
        String rightShift2 = leftShift(rightShift1, 2);
        String key2 = permute(leftShift2 + rightShift2, SDesConstants.P8);

        return new String[]{key1, key2};
    }

    /**
     * S-DES 的核心处理（加密/解密共用）。
     *
     * <p>流程：IP → f_K(firstKey) → SW → f_K(secondKey) → IP⁻¹。</p>
     *
     * <p>加密时 firstKey=K1, secondKey=K2；
     * 解密时 firstKey=K2, secondKey=K1。</p>
     *
     * @param input     8 位输入
     * @param firstKey  第一轮子密钥
     * @param secondKey 第二轮子密钥
     * @return 8 位输出
     */
    private String process(String input, String firstKey, String secondKey) {
        // 1. 初始置换 IP
        String permuted = permute(input, SDesConstants.IP);

        // 2. 分成左右两部分
        String leftHalf = permuted.substring(0, 4);
        String rightHalf = permuted.substring(4);

        // 3. 第一轮 F 函数
        String afterRound1 = fFunction(leftHalf, rightHalf, firstKey);
        leftHalf = afterRound1.substring(0, 4);
        rightHalf = afterRound1.substring(4);

        // 4. SW 交换（只在两轮之间做一次）
        String temp = leftHalf;
        leftHalf = rightHalf;
        rightHalf = temp;

        // 5. 第二轮 F 函数
        String afterRound2 = fFunction(leftHalf, rightHalf, secondKey);
        leftHalf = afterRound2.substring(0, 4);
        rightHalf = afterRound2.substring(4);

        // 6. 拼接后做最终置换 IP⁻¹
        return permute(leftHalf + rightHalf, SDesConstants.IP_INVERSE);
    }

    /**
     * 轮函数 F_K：把左右 4 位做一轮变换。
     *
     * <p>计算结果：(L XOR F(R, K), R)。此处不含 SW。</p>
     *
     * @param leftHalf  左 4 位
     * @param rightHalf 右 4 位
     * @param subKey    8 位子密钥
     * @return 8 位结果（新左半 + 原右半）
     */
    private String fFunction(String leftHalf, String rightHalf, String subKey) {
        // 1. EP 扩展：4 位 → 8 位
        String expanded = permute(rightHalf, SDesConstants.EP_BOX);

        // 2. 与子密钥异或
        String xored = xor(expanded, subKey);

        // 3. 分成左右各 4 位，分别过 S 盒
        String leftNibble = xored.substring(0, 4);
        String rightNibble = xored.substring(4);

        String sBoxOut1 = applySBox(leftNibble, SDesConstants.S_BOX_1);
        String sBoxOut2 = applySBox(rightNibble, SDesConstants.S_BOX_2);

        // 4. SP 盒（即 P4）置换
        String spOut = permute(sBoxOut1 + sBoxOut2, SDesConstants.SP_BOX);

        // 5. 与左半异或，得到新左半
        String newLeftHalf = xor(leftHalf, spOut);

        // 6. 返回 (新左半 + 原右半)
        return newLeftHalf + rightHalf;
    }

    /**
     * 通用置换：按表从输入串中挑选位。
     *
     * @param input 输入二进制串
     * @param table 置换表（1-based）
     * @return 置换后的二进制串
     */
    private String permute(String input, int[] table) {
        StringBuilder result = new StringBuilder(table.length);
        for (int position : table) {
            result.append(input.charAt(position - 1));
        }
        return result.toString();
    }

    /**
     * 循环左移。
     *
     * @param input 输入串
     * @param count 左移位数
     * @return 移位后的串
     */
    private String leftShift(String input, int count) {
        int length = input.length();
        int shift = count % length;
        return input.substring(shift) + input.substring(0, shift);
    }

    /**
     * 两个二进制串逐位异或。
     *
     * @param first  串 a
     * @param second 串 b
     * @return 异或结果
     */
    private String xor(String first, String second) {
        StringBuilder result = new StringBuilder(first.length());
        for (int i = 0; i < first.length(); i++) {
            result.append(first.charAt(i) == second.charAt(i) ? '0' : '1');
        }
        return result.toString();
    }

    /**
     * S 盒查表：4 位输入 → 2 位输出。
     *
     * @param input 4 位输入
     * @param sBox  S 盒
     * @return 2 位输出
     */
    private String applySBox(String input, int[][] sBox) {
        // 第 1、4 位组成行号；第 2、3 位组成列号
        int row = Integer.parseInt("" + input.charAt(0) + input.charAt(3), 2);
        int column = Integer.parseInt("" + input.charAt(1) + input.charAt(2), 2);
        int value = sBox[row][column];
        return String.format("%2s", Integer.toBinaryString(value)).replace(' ', '0');
    }

    /**
     * 校验二进制串长度和内容。
     *
     * @param binary 待校验串
     * @param length 期望长度
     * @param name   字段名（用于报错信息）
     */
    private void validateBinary(String binary, int length, String name) {
        if (binary == null || binary.length() != length || !binary.matches("[01]+")) {
            throw new IllegalArgumentException(name + "必须是长度为 " + length + " 的二进制串");
        }
    }
}