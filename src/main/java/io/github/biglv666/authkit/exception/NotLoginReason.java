package io.github.biglv666.authkit.exception;

/**
 * 未登录原因枚举。
 * <p>前端可凭 reason 区分处理：NO_TOKEN/TOKEN_INVALID → 引导登录；
 * TOKEN_TIMEOUT → 会话过期重新登录；KICKED_OUT/BE_REPLACED → 提示"已在别处登录"。</p>
 */
public enum NotLoginReason {

    /** 请求未携带 token */
    NO_TOKEN("未提供登录凭证"),
    /** token 无效（不存在或格式非法） */
    TOKEN_INVALID("登录凭证无效"),
    /** token 有效但长期未活跃，已超活跃超时时间 */
    TOKEN_TIMEOUT("登录已过期，请重新登录"),
    /** 被管理员强制下线 */
    KICKED_OUT("您已被强制下线"),
    /** 同端新登录顶掉了旧会话 */
    BE_REPLACED("您的账号在其他设备登录");

    private final String defaultMessage;

    NotLoginReason(String defaultMessage) {
        this.defaultMessage = defaultMessage;
    }

    /** 默认提示文案（可通过 auth-kit.session.kicked-out-message 覆盖被踢/被顶文案） */
    public String getDefaultMessage() {
        return defaultMessage;
    }
}
