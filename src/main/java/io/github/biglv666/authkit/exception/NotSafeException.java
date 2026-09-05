package io.github.biglv666.authkit.exception;

/**
 * 未通过二级认证异常：标注 @RequireSafe 的端点在安全态之外被访问时抛出。
 * <p>业务方应引导用户重新验密后调用 {@code AuthKit.openSafe()}。</p>
 */
public class NotSafeException extends RuntimeException {

    public NotSafeException() {
        super("该操作需要安全验证，请先重新输入密码");
    }

    public NotSafeException(String message) {
        super(message);
    }
}
