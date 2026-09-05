package io.github.biglv666.authkit.exception;

/**
 * 登录锁定异常：连续登录失败触发防爆破锁定，由 {@code LoginAttemptGuard.check()} 抛出。
 * <p>业务方在登录逻辑中自行决定是否捕获处理（通常直接向上抛，由统一异常处理返回给前端）。</p>
 */
public class LoginLockedException extends RuntimeException {

    /** 距离解锁剩余毫秒数 */
    private final long remainingMillis;

    public LoginLockedException(String message, long remainingMillis) {
        super(message);
        this.remainingMillis = remainingMillis;
    }

    /** 距离解锁剩余毫秒数 */
    public long getRemainingMillis() {
        return remainingMillis;
    }
}
