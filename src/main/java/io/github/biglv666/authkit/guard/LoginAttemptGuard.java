package io.github.biglv666.authkit.guard;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.exception.LoginLockedException;

/**
 * 登录失败防爆破守卫：三段式插桩，由业务方在登录逻辑中自行调用。
 * <pre>{@code
 * loginGuard.check(username);          // 1. 登录前：已锁定则抛 LoginLockedException
 * boolean ok = verifyPassword(...);
 * if (ok) {
 *     loginGuard.recordSuccess(username);  // 2a. 成功：清除失败计数
 *     AuthKit.login(userId);
 * } else {
 *     loginGuard.recordFailure(username);  // 2b. 失败：累计计数
 * }
 * }</pre>
 * <p>计数走 {@link AttemptStore} SPI（自动装配提供 Redis/内存实现）。</p>
 */
public class LoginAttemptGuard {

    private static final String KEY_PREFIX = "auth-kit:attempt:";

    private final AttemptStore attemptStore;
    private final int failMaxAttempts;
    private final long lockDurationMillis;

    public LoginAttemptGuard(AttemptStore attemptStore, int failMaxAttempts, long lockDurationMillis) {
        this.attemptStore = attemptStore;
        this.failMaxAttempts = failMaxAttempts;
        this.lockDurationMillis = lockDurationMillis;
    }

    /** 防爆破是否启用（fail-max-attempts <= 0 时关闭） */
    public boolean isEnabled() {
        return failMaxAttempts > 0;
    }

    /**
     * 登录前检查：若该标识处于锁定窗口内则抛出 {@link LoginLockedException}。
     *
     * @param identifier 防爆破标识（通常是用户名/手机号）
     */
    public void check(String identifier) {
        if (!isEnabled()) {
            return;
        }
        long count = attemptStore.get(key(identifier));
        if (count >= failMaxAttempts) {
            long remainingMinutes = Math.max(1, lockDurationMillis / 60000);
            throw new LoginLockedException(
                    "登录失败次数过多，账户已锁定，请约 " + remainingMinutes + " 分钟后再试", lockDurationMillis);
        }
    }

    /**
     * 记录一次登录失败。
     */
    public void recordFailure(String identifier) {
        if (!isEnabled()) {
            return;
        }
        attemptStore.incr(key(identifier), lockDurationMillis);
    }

    /**
     * 登录成功：清除该标识的失败计数。
     */
    public void recordSuccess(String identifier) {
        attemptStore.clear(key(identifier));
    }

    /** 标识直接进入 key，避免歧义时业务方可先做规范化（如统一大小写） */
    private String key(String identifier) {
        return KEY_PREFIX + identifier;
    }
}
