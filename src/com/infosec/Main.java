package com.infosec;

import com.infosec.gui.MainFrame;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * 程序入口：启动 S-DES 图形界面。
 */
public class Main {

    public static void main(String[] args) {
        // 让界面使用系统默认外观，更美观
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // 使用默认外观即可，不影响功能
        }
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }
}