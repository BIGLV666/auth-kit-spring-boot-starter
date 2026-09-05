package io.github.biglv666.authkit.model;

/**
 * 登录会话模型：一个 token 对应一条会话。
 * <p>字段以 Hash 形式存储于 Redis（或内存 Map），均为简单类型，
 * 不依赖任何序列化框架，跨版本兼容。</p>
 */
public class AuthSession {

    /** 登录凭证（不透明随机 token） */
    private String token;
    /** 登录用户标识（字符串存储，业务方可自行转换数值类型） */
    private String userId;
    /** 登录设备标识 */
    private String device;
    /** 登录时间戳（毫秒） */
    private long loginTime;
    /** 最后活跃时间戳（毫秒），用于滑动续期与活跃超时判定 */
    private long lastActiveTime;

    public AuthSession() {
    }

    public AuthSession(String token, String userId, String device, long loginTime, long lastActiveTime) {
        this.token = token;
        this.userId = userId;
        this.device = device;
        this.loginTime = loginTime;
        this.lastActiveTime = lastActiveTime;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getDevice() {
        return device;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public long getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(long loginTime) {
        this.loginTime = loginTime;
    }

    public long getLastActiveTime() {
        return lastActiveTime;
    }

    public void setLastActiveTime(long lastActiveTime) {
        this.lastActiveTime = lastActiveTime;
    }
}
