package com.infosec.util;

import java.util.function.Function;

/**
 * 公共加密工具类，体现函数式编程思想。
 */
public class CryptoUtils {

    /**
     * 通用字符映射：把每个字符按给定函数转换。
     *
     * @param input      输入字符串
     * @param charMapper 字符转换函数
     * @return 转换后的字符串
     */
    public static String mapCharacters(String input, Function<Character, Character> charMapper) {
        StringBuilder result = new StringBuilder(input.length());
        for (char c : input.toCharArray()) {
            result.append(charMapper.apply(c));
        }
        return result.toString();
    }
}