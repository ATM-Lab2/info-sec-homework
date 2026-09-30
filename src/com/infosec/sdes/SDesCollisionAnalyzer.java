package com.infosec.sdes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 关卡5：分析 S-DES 是否存在多个密钥加密同一明文得到相同密文的情况。
 */
public class SDesCollisionAnalyzer {

    private static final int KEY_SPACE = 1024;

    private final SDesAlgorithm algorithm = new SDesAlgorithm();

    /**
     * 对给定明文，统计所有生成相同密文的不同密钥。
     *
     * @param plainText 8 位明文
     * @return 密文 → 所有匹配密钥列表（只包含数量大于 1 的）
     */
    public Map<String, List<String>> analyzeCollisions(String plainText) {
        Map<String, List<String>> cipherToKeys = new HashMap<>();

        for (int keyValue = 0; keyValue < KEY_SPACE; keyValue++) {
            String key = toKeyString(keyValue);
            String cipher = algorithm.encrypt(plainText, key);
            cipherToKeys.computeIfAbsent(cipher, k -> new ArrayList<>()).add(key);
        }

        Map<String, List<String>> collisions = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : cipherToKeys.entrySet()) {
            if (entry.getValue().size() > 1) {
                collisions.put(entry.getKey(), entry.getValue());
            }
        }
        return collisions;
    }

    private String toKeyString(int value) {
        return String.format("%10s", Integer.toBinaryString(value)).replace(' ', '0');
    }
}