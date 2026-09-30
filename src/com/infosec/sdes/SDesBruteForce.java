package com.infosec.sdes;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 关卡4：暴力破解 S-DES 的 10 位密钥。
 *
 * <p>密钥空间共 2^10 = 1024 种，提供串行与多线程两种实现。</p>
 */
public class SDesBruteForce {

    private static final int KEY_SPACE = 1024;

    private final SDesAlgorithm algorithm = new SDesAlgorithm();

    /**
     * 串行暴力破解。
     */
    public List<String> bruteForce(String plainText, String cipherText) {
        List<String> foundKeys = new ArrayList<>();
        for (int keyValue = 0; keyValue < KEY_SPACE; keyValue++) {
            String key = toKeyString(keyValue);
            if (cipherText.equals(algorithm.encrypt(plainText, key))) {
                foundKeys.add(key);
            }
        }
        return foundKeys;
    }

    /**
     * 多线程暴力破解。
     */
    public List<String> bruteForceParallel(String plainText, String cipherText)
            throws InterruptedException {
        List<String> foundKeys = new ArrayList<>();
        int threadCount = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        int chunkSize = KEY_SPACE / threadCount;

        for (int i = 0; i < threadCount; i++) {
            int start = i * chunkSize;
            int end = (i == threadCount - 1) ? KEY_SPACE : start + chunkSize;

            executor.submit(() -> {
                for (int keyValue = start; keyValue < end; keyValue++) {
                    String key = toKeyString(keyValue);
                    if (cipherText.equals(algorithm.encrypt(plainText, key))) {
                        synchronized (foundKeys) {
                            foundKeys.add(key);
                        }
                    }
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);
        return foundKeys;
    }

    private String toKeyString(int value) {
        return String.format("%10s", Integer.toBinaryString(value)).replace(' ', '0');
    }
}