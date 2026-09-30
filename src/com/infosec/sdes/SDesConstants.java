package com.infosec.sdes;

/**
 * S-DES 算法的全部常量表（置换盒、S盒）。
 *
 * <p>所有表均采用 1-based 索引，与课程 PPT 一致。</p>
 */
public final class SDesConstants {

    private SDesConstants() {
    }

    /** P10：10 位密钥的初始置换 */
    public static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};

    /** P8：从 10 位中选出 8 位作为子密钥 */
    public static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};

    /** SPBox（即 P4）：轮函数中的 4 位置换 */
    public static final int[] SP_BOX = {2, 4, 3, 1};

    /** IP：8 位初始置换 */
    public static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};

    /** IP⁻¹：8 位最终置换 */
    public static final int[] IP_INVERSE = {4, 1, 3, 5, 7, 2, 8, 6};

    /** EPBox：扩展置换，把 4 位扩展为 8 位 */
    public static final int[] EP_BOX = {4, 1, 2, 3, 2, 3, 4, 1};

    /** SBox1：按 PPT 规定 */
    public static final int[][] S_BOX_1 = {
            {1, 0, 3, 2},
            {3, 2, 1, 0},
            {0, 2, 1, 3},
            {3, 1, 0, 2}
    };

    /** SBox2：按 PPT 规定（注意：与旧版有改动） */
    public static final int[][] S_BOX_2 = {
            {0, 1, 2, 3},
            {2, 3, 1, 0},
            {3, 0, 1, 2},
            {2, 1, 0, 3}
    };
}