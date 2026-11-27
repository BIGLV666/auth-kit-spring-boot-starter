package io.github.biglv666.authkit.event;

/**
 * 认证审计事件：登录成功、登录失败、触发锁定/风控。
 *
 * <p>只承载业务标识与原因，<b>不包含 token、密码或任何凭证</b>，可安全写入审计日志或上报指标。
 * 由 {@code AuthManager}（登录成功）与 {@code LoginAttemptGuard}（失败/锁定）发布；
 * 会话生命周期事件见 {@link AuthKitSessionEvent}。</p>
 */
public class AuthKitAuditEvent {

    /** 审计动作 */
    public enum Action {
        /** 登录成功 */
        LOGIN_SUCCESS,
        /** 密码/凭证校验失败 */
        LOGIN_FAILURE,
        /** 触发锁定或风控封禁 */
        LOCKED_OUT
    }

    private final Action action;
    /** 登录成功时为 userId；失败/锁定时为业务传入的登录标识（如用户名、手机号） */
    private final String identifier;
    /** 设备标识，未提供时为 null */
    private final String device;
    /** 附加原因（如剩余锁定毫秒数），可为 null */
    private final String reason;

    public AuthKitAuditEvent(Action action, String identifier, String device, String reason) {
        this.action = action;
        this.identifier = identifier;
        this.device = device;
        this.reason = reason;
    }

    public Action getAction() {
        return action;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getDevice() {
        return device;
    }

    public String getReason() {
        return reason;
    }

    @Override
    public String toString() {
        return "AuthKitAuditEvent{" + action
                + ", identifier=" + identifier
                + ", device=" + device
                + (reason == null ? "" : ", reason=" + reason)
                + '}';
    }
}
