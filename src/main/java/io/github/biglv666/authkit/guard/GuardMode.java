package io.github.biglv666.authkit.guard;

/**
 * 防爆破模式。
 */
public enum GuardMode {
    /** 固定窗口计数（默认，兼容既有行为）。 */
    COUNTER,
    /** 滑动尝试窗口 + 递增风控。 */
    RISK_CONTROL
}
