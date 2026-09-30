package com.infosec;

import com.infosec.sdes.SDesStringCodec;

/**
 * 命令行测试关卡3：字符串加解密往返。
 */
public class TestString {

    public static void main(String[] args) {
        SDesStringCodec codec = new SDesStringCodec();

        String key = "1010101010";
        String[] testCases = {
                "Hello",
                "This is a test",
                "信息安全",
                "1234567890"
        };

        for (String plain : testCases) {
            String cipher = codec.encryptString(plain, key);
            String decoded = codec.decryptString(cipher, key);
            boolean ok = plain.equals(decoded);
            System.out.println("明文=[" + plain + "] 长度=" + plain.length()
                    + " 密钥=" + key
                    + " → 密文(转义)=" + escapeUnicode(cipher)
                    + " → 解密=[" + decoded + "] 是否还原: " + (ok ? "OK" : "FAIL"));
        }
    }

    /**
     * 把字符串中非打印字符转义成 Unicode 十六进制形式。
     */
    private static String escapeUnicode(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 0x20 && c <= 0x7E) {
                sb.append(c);
            } else {
                sb.append(String.format("\\u%04X", (int) c));
            }
        }
        return sb.toString();
    }
}