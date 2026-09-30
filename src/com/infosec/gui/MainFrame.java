package com.infosec.gui;

import com.infosec.sdes.SDesAlgorithm;
import com.infosec.sdes.SDesBruteForce;
import com.infosec.sdes.SDesCollisionAnalyzer;
import com.infosec.sdes.SDesStringCodec;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * S-DES 作业主窗口，包含 5 个关卡标签页。
 */
public class MainFrame extends JFrame {

    private final SDesAlgorithm algorithm = new SDesAlgorithm();
    private final SDesStringCodec codec = new SDesStringCodec();
    private final SDesBruteForce bruteForce = new SDesBruteForce();
    private final SDesCollisionAnalyzer analyzer = new SDesCollisionAnalyzer();

    public MainFrame() {
        setTitle("S-DES 加解密演示 - 信息安全导论作业1");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 680);
        setLocationRelativeTo(null);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("关卡1 基本测试", createBasicPanel());
        tabbedPane.addTab("关卡2 交叉测试", createCrossTestPanel());
        tabbedPane.addTab("关卡3 字符串加解密", createStringPanel());
        tabbedPane.addTab("关卡4 暴力破解", createBruteForcePanel());
        tabbedPane.addTab("关卡5 封闭测试", createCollisionPanel());

        add(tabbedPane);
    }

    /** 关卡1：8 位明文 + 10 位密钥，加解密。 */
    private JPanel createBasicPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField plainField = new JTextField("00000000", 22);
        JTextField keyField = new JTextField("0000000000", 22);
        JTextArea resultArea = new JTextArea(8, 50);
        resultArea.setEditable(false);

        JButton encryptButton = new JButton("加密");
        JButton decryptButton = new JButton("解密");

        encryptButton.addActionListener(e -> {
            try {
                String cipher = algorithm.encrypt(plainField.getText().trim(), keyField.getText().trim());
                resultArea.setText("明文: " + plainField.getText().trim()
                        + "\n密钥: " + keyField.getText().trim()
                        + "\n密文: " + cipher);
            } catch (Exception ex) {
                resultArea.setText("错误: " + ex.getMessage());
            }
        });

        decryptButton.addActionListener(e -> {
            try {
                String plain = algorithm.decrypt(plainField.getText().trim(), keyField.getText().trim());
                resultArea.setText("密文: " + plainField.getText().trim()
                        + "\n密钥: " + keyField.getText().trim()
                        + "\n明文: " + plain);
            } catch (Exception ex) {
                resultArea.setText("错误: " + ex.getMessage());
            }
        });

        addRow(panel, gbc, 0, "8位明文/密文:", plainField);
        addRow(panel, gbc, 1, "10位密钥:", keyField);
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(encryptButton, gbc);
        gbc.gridx = 1;
        panel.add(decryptButton, gbc);
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        panel.add(new JScrollPane(resultArea), gbc);
        return panel;
    }

    /** 关卡2：交叉测试说明。 */
    private JPanel createCrossTestPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JTextArea info = new JTextArea();
        info.setEditable(false);
        info.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        info.setText("\n关卡2：交叉测试\n\n"
                + "1. 与另一位同学约定相同的 10 位密钥 K；\n\n"
                + "2. 双方分别用自己的程序加密同一 8 位明文 P；\n\n"
                + "3. 若两个程序输出的密文 C 完全一致，说明算法实现一致；\n\n"
                + "4. 再用对方的密文 C 在本程序解密，应得到相同的 P；\n\n"
                + "5. 这样即可验证程序在异构平台上的互操作性。\n\n"
                + "请到【关卡1】页面进行加解密操作，与同学比对结果。");
        panel.add(new JScrollPane(info), BorderLayout.CENTER);
        return panel;
    }

    /** 关卡3：字符串加解密。 */
    private JPanel createStringPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField inputField = new JTextField("Hello S-DES", 30);
        JTextField keyField = new JTextField("1010101010", 22);
        JTextArea resultArea = new JTextArea(8, 50);
        resultArea.setEditable(false);

        JButton encryptButton = new JButton("加密字符串");
        JButton decryptButton = new JButton("解密字符串");

        encryptButton.addActionListener(e -> {
            try {
                String cipher = codec.encryptString(inputField.getText(), keyField.getText().trim());
                resultArea.setText("密文（可能乱码，已用十六进制 Unicode 形式展示）：\n"
                        + escapeUnicode(cipher));
            } catch (Exception ex) {
                resultArea.setText("错误: " + ex.getMessage());
            }
        });

        decryptButton.addActionListener(e -> {
            try {
                String plain = codec.decryptString(inputField.getText(), keyField.getText().trim());
                resultArea.setText("明文:\n" + plain);
            } catch (Exception ex) {
                resultArea.setText("错误: " + ex.getMessage());
            }
        });

        addRow(panel, gbc, 0, "输入字符串:", inputField);
        addRow(panel, gbc, 1, "10位密钥:", keyField);
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(encryptButton, gbc);
        gbc.gridx = 1;
        panel.add(decryptButton, gbc);
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        panel.add(new JScrollPane(resultArea), gbc);
        return panel;
    }

    /** 关卡4：暴力破解（破解时禁用按钮，结束后恢复）。 */
    private JPanel createBruteForcePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField plainField = new JTextField("11010111", 22);
        JTextField cipherField = new JTextField("10001100", 22);
        JTextArea resultArea = new JTextArea(10, 50);
        resultArea.setEditable(false);

        JButton serialButton = new JButton("串行破解");
        JButton parallelButton = new JButton("多线程破解");

        // 串行破解：用 SwingWorker 在后台线程执行，避免阻塞界面
        serialButton.addActionListener(e -> {
            String plain = plainField.getText().trim();
            String cipher = cipherField.getText().trim();
            serialButton.setEnabled(false);
            parallelButton.setEnabled(false);
            resultArea.setText("串行破解中，请稍候...");

            new SwingWorker<Object[], Void>() {
                @Override
                protected Object[] doInBackground() {
                    long start = System.currentTimeMillis();
                    List<String> keys = bruteForce.bruteForce(plain, cipher);
                    long cost = System.currentTimeMillis() - start;
                    return new Object[]{keys, cost};
                }

                @Override
                @SuppressWarnings("unchecked")
                protected void done() {
                    try {
                        Object[] result = get();
                        List<String> keys = (List<String>) result[0];
                        long cost = (Long) result[1];
                        resultArea.setText("串行破解耗时: " + cost + " ms\n"
                                + "找到 " + keys.size() + " 个密钥:\n" + keys);
                    } catch (Exception ex) {
                        resultArea.setText("错误: " + ex.getMessage());
                    } finally {
                        serialButton.setEnabled(true);
                        parallelButton.setEnabled(true);
                    }
                }
            }.execute();
        });

        // 多线程破解：同样在后台线程执行
        parallelButton.addActionListener(e -> {
            String plain = plainField.getText().trim();
            String cipher = cipherField.getText().trim();
            serialButton.setEnabled(false);
            parallelButton.setEnabled(false);
            resultArea.setText("多线程破解中，请稍候...");

            new SwingWorker<Object[], Void>() {
                @Override
                protected Object[] doInBackground() throws Exception {
                    long start = System.currentTimeMillis();
                    List<String> keys = bruteForce.bruteForceParallel(plain, cipher);
                    long cost = System.currentTimeMillis() - start;
                    return new Object[]{keys, cost};
                }

                @Override
                @SuppressWarnings("unchecked")
                protected void done() {
                    try {
                        Object[] result = get();
                        List<String> keys = (List<String>) result[0];
                        long cost = (Long) result[1];
                        resultArea.setText("多线程破解耗时: " + cost + " ms\n"
                                + "找到 " + keys.size() + " 个密钥:\n" + keys);
                    } catch (Exception ex) {
                        resultArea.setText("错误: " + ex.getMessage());
                    } finally {
                        serialButton.setEnabled(true);
                        parallelButton.setEnabled(true);
                    }
                }
            }.execute();
        });

        addRow(panel, gbc, 0, "8位明文:", plainField);
        addRow(panel, gbc, 1, "8位密文:", cipherField);
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(serialButton, gbc);
        gbc.gridx = 1;
        panel.add(parallelButton, gbc);
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        panel.add(new JScrollPane(resultArea), gbc);
        return panel;
    }

    /** 关卡5：封闭测试。 */
    private JPanel createCollisionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextField plainField = new JTextField("00000000", 22);
        JTextArea resultArea = new JTextArea(14, 60);
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JButton analyzeButton = new JButton("分析密钥碰撞");

        analyzeButton.addActionListener(e -> {
            try {
                String plain = plainField.getText().trim();
                Map<String, List<String>> collisions = analyzer.analyzeCollisions(plain);

                StringBuilder sb = new StringBuilder();
                sb.append("明文: ").append(plain).append("\n");
                sb.append("共发现 ").append(collisions.size()).append(" 组碰撞\n\n");

                int count = 0;
                for (Map.Entry<String, List<String>> entry : collisions.entrySet()) {
                    if (count++ >= 10) {
                        sb.append("...（仅显示前10组）\n");
                        break;
                    }
                    sb.append("密文 ").append(entry.getKey())
                            .append(" 来自密钥: ").append(entry.getValue()).append("\n");
                }

                if (collisions.isEmpty()) {
                    sb.append("该明文下没有发现密钥碰撞。\n");
                }
                resultArea.setText(sb.toString());
            } catch (Exception ex) {
                resultArea.setText("错误: " + ex.getMessage());
            }
        });

        addRow(panel, gbc, 0, "8位明文:", plainField);
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2;
        panel.add(analyzeButton, gbc);
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        panel.add(new JScrollPane(resultArea), gbc);
        return panel;
    }

    /** 通用：往 GridBagLayout 面板里加一行"标签 + 输入框"。 */
    private void addRow(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent field) {
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        panel.add(field, gbc);
    }

    /**
     * 把字符串中非打印字符转义成 Unicode 十六进制形式，方便展示乱码。
     */
    private String escapeUnicode(String input) {
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