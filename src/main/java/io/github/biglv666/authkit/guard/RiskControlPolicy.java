package io.github.biglv666.authkit.guard;

import java.util.List;

/**
 * risk-control 模式的策略参数（不可变）。
 *
 * @param attemptWindowMillis        滚动尝试窗口长度
 * @param maxAttempts                窗口内允许的最大尝试次数；&lt;=0 表示停用（与 counter 模式语义一致）
 * @param lockoutDurationsMillis     连续风控的升级时长档位，最后一项为封顶
 * @param lockoutResetIntervalMillis 上一次风控结束后的静默期，超过则连续风控次数清零
 * @param stateTtlMillis             风控状态的基础过期时间
 * @param resetOnSuccess             登录成功是否清空尝试窗口（不清连续风控次数）
 */
public record RiskControlPolicy(
        long attemptWindowMillis,
        int maxAttempts,
        List<Long> lockoutDurationsMillis,
        long lockoutResetIntervalMillis,
        long stateTtlMillis,
        boolean resetOnSuccess) {

    public RiskControlPolicy {
        if (attemptWindowMillis <= 0) {
            throw new IllegalArgumentException("auth-kit.guard.attempt-window 必须大于 0");
        }
        if (lockoutDurationsMillis == null || lockoutDurationsMillis.isEmpty()) {
            throw new IllegalArgumentException("auth-kit.guard.lockout-durations 不能为空");
        }
        for (Long duration : lockoutDurationsMillis) {
            if (duration == null || duration <= 0) {
                throw new IllegalArgumentException("auth-kit.guard.lockout-durations 每项必须大于 0");
            }
        }
        long previous = 0;
        for (Long duration : lockoutDurationsMillis) {
            if (duration < previous) {
                throw new IllegalArgumentException("auth-kit.guard.lockout-durations 必须非递减");
            }
            previous = duration;
        }
        lockoutDurationsMillis = List.copyOf(lockoutDurationsMillis);
        if (lockoutResetIntervalMillis < 0) {
            throw new IllegalArgumentException("auth-kit.guard.lockout-reset-interval 不能小于 0");
        }
        if (stateTtlMillis <= 0) {
            throw new IllegalArgumentException("auth-kit.guard.state-ttl 必须大于 0");
        }
    }

    /**
     * 第 n 次连续风控的时长；超过档位数时重复使用最后一档。
     */
    public long lockoutDurationMillis(int lockoutCount) {
        int index = Math.min(Math.max(lockoutCount, 1), lockoutDurationsMillis.size()) - 1;
        return lockoutDurationsMillis.get(index);
    }

    /**
     * 状态实际 TTL：至少覆盖最长风控 + 静默期 + 尝试窗口，避免风控中途状态被清掉。
     */
    public long effectiveStateTtlMillis() {
        long maxLockout = lockoutDurationsMillis.get(lockoutDurationsMillis.size() - 1);
        return Math.max(stateTtlMillis, maxLockout + lockoutResetIntervalMillis + attemptWindowMillis);
    }
}
