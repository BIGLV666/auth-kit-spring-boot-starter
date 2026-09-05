package io.github.biglv666.authkit.model;

/**
 * 当前登录用户视图对象，由 {@code @CurrentUser} 参数解析器注入 Controller 方法。
 * <p>仅承载认证上下文（userId/设备/token），不含业务资料；
 * 业务资料由业务方按 userId 自行查询。</p>
 */
public class AuthUser {

    /** 登录用户标识 */
    private final String userId;
    /** 登录设备标识 */
    private final String device;
    /** 当前请求携带的 token */
    private final String token;

    public AuthUser(String userId, String device, String token) {
        this.userId = userId;
        this.device = device;
        this.token = token;
    }

    public String getUserId() {
        return userId;
    }

    /** 以 long 形式返回 userId（业务主键为数值类型时使用） */
    public long getUserIdAsLong() {
        return Long.parseLong(userId);
    }

    public String getDevice() {
        return device;
    }

    public String getToken() {
        return token;
    }
}
