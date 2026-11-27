package io.github.biglv666.authkit.guard;

import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.exception.LoginLockedException;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

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
 *
 * <p>默认 counter 模式走 {@link AttemptStore}（固定窗口计数）；risk-control 模式走
 * {@link RiskControlStore}（滑动尝试窗口 + 递增风控）。</p>
 */
public class LoginAttemptGuard {

    private static final String DEFAULT_KEY_PREFIX = "auth-kit";

    private final AttemptStore attemptStore;
    private final RiskControlStore riskControlStore;
    private final RiskControlPolicy riskPolicy;
    private final int failMaxAttempts;
    private final long lockDurationMillis;
    private final String keyPrefix;
    private final boolean enabled;
    private final LongSupplier clock;
    /** 认证审计监听（登录失败/锁定）；支持多个监听器，单个异常不得影响其他监听器或主流程 */
    private final List<Consumer<AuthKitAuditEvent>> auditListeners = new CopyOnWriteArrayList<>();

    public LoginAttemptGuard(AttemptStore attemptStore, int failMaxAttempts, long lockDurationMillis) {
        this(attemptStore, failMaxAttempts, lockDurationMillis, DEFAULT_KEY_PREFIX);
    }

    public LoginAttemptGuard(AttemptStore attemptStore, int failMaxAttempts, long lockDurationMillis,
                             String keyPrefix) {
        this(attemptStore, null, null, failMaxAttempts, lockDurationMillis, keyPrefix,
                failMaxAttempts > 0, System::currentTimeMillis);
    }

    /**
     * risk-control 模式构造器。
     *
     * @param enabled 由 {@code auth-kit.guard.enabled} 与 {@code fail-max-attempts > 0} 共同决定
     */
    public LoginAttemptGuard(RiskControlStore riskControlStore, RiskControlPolicy riskPolicy,
                             String keyPrefix, boolean enabled) {
        this(null, riskControlStore, riskPolicy, 0, 0, keyPrefix,
                enabled && riskPolicy.maxAttempts() > 0, System::currentTimeMillis);
    }

    /** 测试用：可注入时钟。 */
    LoginAttemptGuard(RiskControlStore riskControlStore, RiskControlPolicy riskPolicy,
                      String keyPrefix, boolean enabled, LongSupplier clock) {
        this(null, riskControlStore, riskPolicy, 0, 0, keyPrefix,
                enabled && riskPolicy.maxAttempts() > 0, clock);
    }

    private LoginAttemptGuard(AttemptStore attemptStore, RiskControlStore riskControlStore,
                              RiskControlPolicy riskPolicy, int failMaxAttempts, long lockDurationMillis,
                              String keyPrefix, boolean enabled, LongSupplier clock) {
        this.attemptStore = attemptStore;
        this.riskControlStore = riskControlStore;
        this.riskPolicy = riskPolicy;
        this.failMaxAttempts = failMaxAttempts;
        this.lockDurationMillis = lockDurationMillis;
        this.keyPrefix = (keyPrefix == null || keyPrefix.isBlank()) ? DEFAULT_KEY_PREFIX : keyPrefix;
        this.enabled = enabled;
        this.clock = clock;
    }

    /** 防爆破是否启用 */
    public boolean isEnabled() {
        return enabled;
    }

    /** 覆盖认证审计监听（单监听器语义） */
    public void setAuditListener(Consumer<AuthKitAuditEvent> auditListener) {
        auditListeners.clear();
        if (auditListener != null) {
            auditListeners.add(auditListener);
        }
    }

    /** 追加认证审计监听（自动装配接入指标/审计日志/Spring 事件，互不覆盖） */
    public void addAuditListener(Consumer<AuthKitAuditEvent> auditListener) {
        if (auditListener != null) {
            auditListeners.add(auditListener);
        }
    }

    private void publishAudit(AuthKitAuditEvent.Action action, String identifier, String reason) {
        if (auditListeners.isEmpty()) {
            return;
        }
        AuthKitAuditEvent event = new AuthKitAuditEvent(action, identifier, null, reason);
        for (Consumer<AuthKitAuditEvent> listener : auditListeners) {
            try {
                listener.accept(event);
            } catch (Exception ignored) {
                // 单个监听器异常不得影响其他监听器或主流程
            }
        }
    }

    /**
     * 登录前检查：若该标识处于锁定窗口内则抛出 {@link LoginLockedException}。
     * <p>risk-control 模式下，通过检查会原子占用一次尝试额度；未通过则直接触发/返回风控。</p>
     *
     * @param identifier 防爆破标识（通常是用户名/手机号）
     */
    public void check(String identifier) {
        if (!enabled) {
            return;
        }
        if (riskControlStore != null) {
            RiskDecision decision = riskControlStore.check(key(identifier), riskPolicy, clock.getAsLong());
            if (!decision.allowed()) {
                long remaining = decision.retryAfterMillis();
                publishAudit(AuthKitAuditEvent.Action.LOCKED_OUT, identifier, String.valueOf(remaining));
                throw new LoginLockedException(
                        "尝试次数过多，账户已被风控，请约 " + remainingMinutes(remaining) + " 分钟后再试",
                        remaining);
            }
            return;
        }
        long count = attemptStore.get(key(identifier));
        if (count >= failMaxAttempts) {
            publishAudit(AuthKitAuditEvent.Action.LOCKED_OUT, identifier, String.valueOf(lockDurationMillis));
            throw new LoginLockedException(
                    "登录失败次数过多，账户已锁定，请约 " + remainingMinutes(lockDurationMillis) + " 分钟后再试",
                    lockDurationMillis);
        }
    }

    /**
     * 记录一次登录失败。
     * <p>risk-control 模式下为 no-op：尝试次数已在 {@link #check} 中原子占用。</p>
     */
    public void recordFailure(String identifier) {
        if (!enabled) {
            return;
        }
        if (riskControlStore != null) {
            // risk-control 模式：尝试额度已在 check() 原子占用，这里只补审计事件
            publishAudit(AuthKitAuditEvent.Action.LOGIN_FAILURE, identifier, null);
            return;
        }
        attemptStore.incr(key(identifier), lockDurationMillis);
        publishAudit(AuthKitAuditEvent.Action.LOGIN_FAILURE, identifier, null);
    }

    /**
     * 登录成功：清除失败计数。
     * <p>risk-control 模式下按策略清空尝试窗口，但不清连续风控次数。</p>
     */
    public void recordSuccess(String identifier) {
        if (riskControlStore != null) {
            riskControlStore.recordSuccess(key(identifier), riskPolicy, clock.getAsLong());
            return;
        }
        attemptStore.clear(key(identifier));
    }

    /** counter 与 risk-control 使用不同的 key 命名空间，避免切换模式时类型冲突。 */
    private String key(String identifier) {
        return keyPrefix + (riskControlStore != null ? ":risk:" : ":attempt:") + identifier;
    }

    private static long remainingMinutes(long millis) {
        return Math.max(1, millis / 60_000);
    }
}
