package io.github.biglv666.authkit.exception;

/**
 * 未登录异常（含被踢下线、被顶下线、token 过期等场景，以 {@link #getReason()} 区分）。
 */
public class NotLoginException extends RuntimeException {

    private final NotLoginReason reason;

    public NotLoginException(NotLoginReason reason) {
        super(reason.getDefaultMessage());
        this.reason = reason;
    }

    public NotLoginException(NotLoginReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    /** 未登录的具体原因，供前端区分处理 */
    public NotLoginReason getReason() {
        return reason;
    }
}
