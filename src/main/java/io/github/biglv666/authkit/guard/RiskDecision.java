package io.github.biglv666.authkit.guard;

/**
 * 一次风控检查的判定结果。
 *
 * @param allowed            是否放行
 * @param retryAfterMillis   被风控时距离可再次尝试的剩余毫秒数
 * @param attemptCount       当前尝试窗口内已占用的次数
 * @param lockoutCount       当前连续风控次数
 */
public record RiskDecision(boolean allowed, long retryAfterMillis, int attemptCount, int lockoutCount) {

    public static RiskDecision allowed(int attemptCount, int lockoutCount) {
        return new RiskDecision(true, 0, attemptCount, lockoutCount);
    }

    public static RiskDecision locked(long retryAfterMillis, int attemptCount, int lockoutCount) {
        return new RiskDecision(false, Math.max(1, retryAfterMillis), attemptCount, lockoutCount);
    }
}
