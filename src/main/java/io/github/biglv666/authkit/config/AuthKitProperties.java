package io.github.biglv666.authkit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * auth-kit 配置项（前缀 auth-kit），全部有默认值，零配置可跑。
 */
@ConfigurationProperties(prefix = "auth-kit")
public class AuthKitProperties {

    /** 组件总开关 */
    private boolean enabled = true;

    private final Token token = new Token();
    private final Session session = new Session();
    private final Guard guard = new Guard();
    private final Management management = new Management();
    /** 放行路径白名单（Ant 风格） */
    private List<String> whitelist = new ArrayList<>(List.of("/login", "/actuator/**"));

    /** token 相关配置 */
    public static class Token {
        /** 读取 token 的请求头名称 */
        private String headerName = "Authorization";
        /** 读取 token 的 Cookie 名称；空表示不读 Cookie */
        private String cookieName = "";
        /** 请求头前缀（如 Bearer），剥离大小写不敏感；空表示裸 token */
        private String prefix = "Bearer";
        /** 会话绝对有效期 */
        private Duration timeout = Duration.ofDays(30);
        /** 活跃超时（滑动续期）：超过该时长无任何请求即失效；0 表示不启用 */
        private Duration activeTimeout = Duration.ofDays(7);
        /** token 生成策略标识（V1 支持 random-64；扩展走 TokenGenerator SPI） */
        private String style = "random-64";

        public String getHeaderName() {
            return headerName;
        }

        public String getCookieName() {
            return cookieName;
        }

        public String getPrefix() {
            return prefix;
        }

        public Duration getTimeout() {
            return timeout;
        }

        public Duration getActiveTimeout() {
            return activeTimeout;
        }

        public String getStyle() {
            return style;
        }

        public void setHeaderName(String headerName) {
            this.headerName = headerName;
        }

        public void setCookieName(String cookieName) {
            this.cookieName = cookieName;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }

        public void setTimeout(Duration timeout) {
            this.timeout = timeout;
        }

        public void setActiveTimeout(Duration activeTimeout) {
            this.activeTimeout = activeTimeout;
        }

        public void setStyle(String style) {
            this.style = style;
        }
    }

    /** 会话相关配置 */
    public static class Session {
        /** 存储实现：auto（有 Redis 用 Redis，否则内存）/ redis / memory */
        private String store = "auto";
        /** 同端最大会话数：1=顶号，-1=不限，n=保留最近 n 个 */
        private int maxSessionsPerDevice = 1;
        /** 被顶下线时旧端收到的提示文案 */
        private String kickedOutMessage = "您已在其他设备登录";
        /** Redis key 前缀 */
        private String keyPrefix = "auth-kit";

        public String getStore() {
            return store;
        }

        public void setStore(String store) {
            this.store = store;
        }

        public int getMaxSessionsPerDevice() {
            return maxSessionsPerDevice;
        }

        public void setMaxSessionsPerDevice(int maxSessionsPerDevice) {
            this.maxSessionsPerDevice = maxSessionsPerDevice;
        }

        public String getKickedOutMessage() {
            return kickedOutMessage;
        }

        public void setKickedOutMessage(String kickedOutMessage) {
            this.kickedOutMessage = kickedOutMessage;
        }

        public String getKeyPrefix() {
            return keyPrefix;
        }

        public void setKeyPrefix(String keyPrefix) {
            this.keyPrefix = keyPrefix;
        }
    }

    /** 登录防爆破配置 */
    public static class Guard {
        /** 防爆破开关（配合 LoginAttemptGuard 使用） */
        private boolean enabled = true;
        /** 最大连续失败次数，超过即锁定；<=0 关闭 */
        private int failMaxAttempts = 5;
        /** 锁定时长 */
        private Duration lockDuration = Duration.ofMinutes(15);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getFailMaxAttempts() {
            return failMaxAttempts;
        }

        public void setFailMaxAttempts(int failMaxAttempts) {
            this.failMaxAttempts = failMaxAttempts;
        }

        public Duration getLockDuration() {
            return lockDuration;
        }

        public void setLockDuration(Duration lockDuration) {
            this.lockDuration = lockDuration;
        }
    }

    /** 管理端点配置 */
    public static class Management {
        /** 是否启用管理端点（在线会话查询/强制下线） */
        private boolean enabled = false;
        /** 管理端点静态令牌；启用时必填 */
        private String authToken = "";
        /** 静态令牌请求头名称 */
        private String authHeader = "X-Auth-Kit-Token";
        /** 管理端点基础路径 */
        private String basePath = "/auth-kit";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getAuthToken() {
            return authToken;
        }

        public void setAuthToken(String authToken) {
            this.authToken = authToken;
        }

        public String getAuthHeader() {
            return authHeader;
        }

        public void setAuthHeader(String authHeader) {
            this.authHeader = authHeader;
        }

        public String getBasePath() {
            return basePath;
        }

        public void setBasePath(String basePath) {
            this.basePath = basePath;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Token getToken() {
        return token;
    }

    public Session getSession() {
        return session;
    }

    public Guard getGuard() {
        return guard;
    }

    public Management getManagement() {
        return management;
    }

    public List<String> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    public String getHeaderName() {
        return token.headerName;
    }

    public String getCookieName() {
        return token.cookieName;
    }

    public String getPrefix() {
        return token.prefix;
    }

    public Duration getTimeout() {
        return token.timeout;
    }

    public Duration getActiveTimeout() {
        return token.activeTimeout;
    }

    public String getStore() {
        return session.store;
    }

    public int getMaxSessionsPerDevice() {
        return session.maxSessionsPerDevice;
    }

    public String getKickedOutMessage() {
        return session.kickedOutMessage;
    }

    public String getKeyPrefix() {
        return session.keyPrefix;
    }

    public boolean isGuardEnabled() {
        return guard.enabled;
    }

    public int getFailMaxAttempts() {
        return guard.failMaxAttempts;
    }

    public Duration getLockDuration() {
        return guard.lockDuration;
    }

    public boolean isManagementEnabled() {
        return management.enabled;
    }

    public String getAuthToken() {
        return management.authToken;
    }

    public String getAuthHeader() {
        return management.authHeader;
    }

    public String getBasePath() {
        return management.basePath;
    }
}
