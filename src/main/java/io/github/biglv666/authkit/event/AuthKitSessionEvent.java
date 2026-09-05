package io.github.biglv666.authkit.event;

/**
 * 会话生命周期事件（POJO，不依赖 Spring 类型）：登出/踢人/顶号时由 AuthManager 发布。
 * <p>SSO 场景各应用共享同一 Redis 会话，凭证失效天然全局生效；
 * 本事件用于应用本地附加清理（如缓存失效、WebSocket 主动断开）。</p>
 */
public class AuthKitSessionEvent {

    /** 动作类型 */
    public enum Action { LOGOUT, KICKED_OUT, FORCED_LOGOUT, REPLACED }

    private final String userId;
    private final String credential;
    private final Action action;

    public AuthKitSessionEvent(String userId, String credential, Action action) {
        this.userId = userId;
        this.credential = credential;
        this.action = action;
    }

    public String getUserId() {
        return userId;
    }

    /** 失效的凭证（opaque 模式为 token；JWT 模式为凭证本身） */
    public String getCredential() {
        return credential;
    }

    public Action getAction() {
        return action;
    }
}
