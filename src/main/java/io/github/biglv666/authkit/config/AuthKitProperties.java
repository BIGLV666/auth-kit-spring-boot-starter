package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.guard.GuardMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    private final Safe safe = new Safe();
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
        /** token 模式：opaque（不透明随机 token，默认）/ jwt（自校验签名 token，走墓碑黑名单） */
        private String mode = "opaque";
        /** JWT 模式的 HS256 签名密钥；mode=jwt 时必填 */
        private String jwtSecret = "";
        /** 记住我会话的有效期（覆盖 timeout） */
        private Duration rememberTimeout = Duration.ofDays(30);

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

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public String getJwtSecret() {
            return jwtSecret;
        }

        public void setJwtSecret(String jwtSecret) {
            this.jwtSecret = jwtSecret;
        }

        public Duration getRememberTimeout() {
            return rememberTimeout;
        }

        public void setRememberTimeout(Duration rememberTimeout) {
            this.rememberTimeout = rememberTimeout;
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
        /** 按设备覆盖的会话上限（key=设备标识，value=上限；未命中的设备用 max-sessions-per-device） */
        private Map<String, Integer> deviceMaxSessions = new HashMap<>();

        public String getStore() {
            return store;
        }

        public void setStore(String store) {
            this.store = store;
        }

        public Map<String, Integer> getDeviceMaxSessions() {
            return deviceMaxSessions;
        }

        public void setDeviceMaxSessions(Map<String, Integer> deviceMaxSessions) {
            this.deviceMaxSessions = deviceMaxSessions;
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
        /** 防爆破模式：counter（默认，固定窗口计数）/ risk-control（滑动尝试窗口 + 递增风控） */
        private GuardMode mode = GuardMode.COUNTER;
        /** 防爆破开关（配合 LoginAttemptGuard 使用） */
        private boolean enabled = true;
        /** counter：最大连续失败次数；risk-control：每个尝试窗口允许的最大尝试次数；<=0 关闭 */
        private int failMaxAttempts = 5;
        /** counter 模式的锁定时长 = 计数窗口 */
        private Duration lockDuration = Duration.ofMinutes(15);
        /** risk-control：滚动尝试窗口 */
        private Duration attemptWindow = Duration.ofMinutes(5);
        /** risk-control：连续风控的升级时长档位，最后一项为封顶 */
        private List<Duration> lockoutDurations = new ArrayList<>(List.of(
                Duration.ofMinutes(5),
                Duration.ofMinutes(15),
                Duration.ofHours(1),
                Duration.ofHours(6),
                Duration.ofHours(24)));
        /** risk-control：上一次风控结束后的静默期，超过则连续风控次数清零 */
        private Duration lockoutResetInterval = Duration.ofHours(6);
        /** risk-control：带风控历史的状态过期时间（普通尝试状态使用更短的 TTL） */
        private Duration stateTtl = Duration.ofHours(31);
        /** risk-control：登录成功是否清空尝试窗口（不清连续风控次数） */
        private boolean resetOnSuccess = true;

        public GuardMode getMode() {
            return mode;
        }

        public void setMode(GuardMode mode) {
            this.mode = mode;
        }

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

        public Duration getAttemptWindow() {
            return attemptWindow;
        }

        public void setAttemptWindow(Duration attemptWindow) {
            this.attemptWindow = attemptWindow;
        }

        public List<Duration> getLockoutDurations() {
            return lockoutDurations;
        }

        public void setLockoutDurations(List<Duration> lockoutDurations) {
            this.lockoutDurations = lockoutDurations;
        }

        public Duration getLockoutResetInterval() {
            return lockoutResetInterval;
        }

        public void setLockoutResetInterval(Duration lockoutResetInterval) {
            this.lockoutResetInterval = lockoutResetInterval;
        }

        public Duration getStateTtl() {
            return stateTtl;
        }

        public void setStateTtl(Duration stateTtl) {
            this.stateTtl = stateTtl;
        }

        public boolean isResetOnSuccess() {
            return resetOnSuccess;
        }

        public void setResetOnSuccess(boolean resetOnSuccess) {
            this.resetOnSuccess = resetOnSuccess;
        }
    }

    /** 二级认证配置 */
    public static class Safe {
        /** 二级认证有效期：openSafe 后该时长内 @RequireSafe 端点免二次验证；0=永久（不推荐） */
        private Duration duration = Duration.ofMinutes(5);

        public Duration getDuration() {
            return duration;
        }

        public void setDuration(Duration duration) {
            this.duration = duration;
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

    public Safe getSafe() {
        return safe;
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

    public Duration getRememberTimeout() {
        return token.rememberTimeout;
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
