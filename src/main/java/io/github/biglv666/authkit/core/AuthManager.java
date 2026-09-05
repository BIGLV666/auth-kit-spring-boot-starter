package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.dao.SafeStore;
import io.github.biglv666.authkit.model.AuthMode;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.authkit.exception.NotRoleException;
import io.github.biglv666.authkit.exception.NotSafeException;
import io.github.biglv666.authkit.model.AuthSession;
import io.github.biglv666.authkit.model.DeviceType;
import io.github.biglv666.authkit.spi.PermissionProvider;
import io.github.biglv666.authkit.token.OpaqueTokenCodec;
import io.github.biglv666.authkit.token.TokenCodec;
import io.github.biglv666.authkit.token.TokenGenerator;
import io.github.biglv666.authkit.dao.SessionDao;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * 认证核心逻辑：签发、校验、续期、踢人、顶号、权限/角色校验、二级认证。
 * <p>支持两种凭证模式（{@link TokenCodec}）：opaque（默认，会话读取校验，全功能）
 * 与 jwt（自校验，验签 + 墓碑黑名单，无滑动续期）。时间源可注入，便于测试。</p>
 */
public class AuthManager {

    private final SessionDao sessionDao;
    private final TokenGenerator tokenGenerator;
    private final long timeoutMillis;
    private final long activeTimeoutMillis;
    private final int maxSessionsPerDevice;
    private final long rememberTimeoutMillis;
    private final long safeDurationMillis;
    private final LongSupplier clock;

    /** 按设备覆盖的会话上限（key=设备标识），未命中用 maxSessionsPerDevice */
    private volatile Map<String, Integer> deviceMaxSessions = Map.of();
    private volatile PermissionProvider permissionProvider;
    private volatile SafeStore safeStore;
    private volatile TokenCodec tokenCodec = new OpaqueTokenCodec();
    /** 可选的 Spring 事件发布器：登出/踢人/顶号时发布 AuthKitSessionEvent（SSO 本地清理用） */
    private volatile java.util.function.Consumer<io.github.biglv666.authkit.event.AuthKitSessionEvent> eventListener;

    public AuthManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                       long timeoutMillis, long activeTimeoutMillis, int maxSessionsPerDevice) {
        this(sessionDao, tokenGenerator, timeoutMillis, activeTimeoutMillis, maxSessionsPerDevice,
                timeoutMillis, 0, System::currentTimeMillis);
    }

    /** 含记住我与二级认证时长的构造（系统时钟） */
    public AuthManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                       long timeoutMillis, long activeTimeoutMillis, int maxSessionsPerDevice,
                       long rememberTimeoutMillis, long safeDurationMillis) {
        this(sessionDao, tokenGenerator, timeoutMillis, activeTimeoutMillis, maxSessionsPerDevice,
                rememberTimeoutMillis, safeDurationMillis, System::currentTimeMillis);
    }

    /** 全参构造：时间源与各时长可注入，供测试模拟时间流逝 */
    public AuthManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                       long timeoutMillis, long activeTimeoutMillis, int maxSessionsPerDevice,
                       long rememberTimeoutMillis, long safeDurationMillis, LongSupplier clock) {
        this.sessionDao = sessionDao;
        this.tokenGenerator = tokenGenerator;
        this.timeoutMillis = timeoutMillis;
        this.activeTimeoutMillis = activeTimeoutMillis;
        this.maxSessionsPerDevice = maxSessionsPerDevice;
        this.rememberTimeoutMillis = rememberTimeoutMillis;
        this.safeDurationMillis = safeDurationMillis;
        this.clock = clock;
    }

    /** 注入权限数据提供者（自动装配时可选注入，缺省则权限校验一律拒绝） */
    public void setPermissionProvider(PermissionProvider permissionProvider) {
        this.permissionProvider = permissionProvider;
    }

    /** 注入二级认证状态存储 */
    public void setSafeStore(SafeStore safeStore) {
        this.safeStore = safeStore;
    }

    /** 注入凭证编解码（opaque / jwt） */
    public void setTokenCodec(TokenCodec tokenCodec) {
        this.tokenCodec = tokenCodec == null ? new OpaqueTokenCodec() : tokenCodec;
    }

    /** 注入按设备覆盖的会话上限 */
    public void setDeviceMaxSessions(Map<String, Integer> deviceMaxSessions) {
        this.deviceMaxSessions = deviceMaxSessions == null ? Map.of() : deviceMaxSessions;
    }

    /** 注册会话事件监听（自动装配接入 Spring 事件广播），可空 */
    public void setEventListener(java.util.function.Consumer<io.github.biglv666.authkit.event.AuthKitSessionEvent> eventListener) {
        this.eventListener = eventListener;
    }

    private void publishEvent(String userId, String credential, io.github.biglv666.authkit.event.AuthKitSessionEvent.Action action) {
        java.util.function.Consumer<io.github.biglv666.authkit.event.AuthKitSessionEvent> listener = eventListener;
        if (listener != null && userId != null) {
            try {
                listener.accept(new io.github.biglv666.authkit.event.AuthKitSessionEvent(userId, credential, action));
            } catch (Exception ignored) {
                // 监听器异常不得影响主流程
            }
        }
    }

    // ── 登录态管理 ──

    /**
     * 登录并签发 token（默认设备 PC，非记住我）。
     *
     * @return 下发给客户端的凭证
     */
    public String login(Object userId) {
        return login(userId, DeviceType.PC.getName(), false);
    }

    /**
     * 登录并签发 token（非记住我）。
     */
    public String login(Object userId, DeviceType deviceType) {
        return login(userId, deviceType.getName(), false);
    }

    /**
     * 登录并签发 token（自定义设备，非记住我）。
     */
    public String login(Object userId, String device) {
        return login(userId, device, false);
    }

    /**
     * 登录并签发 token，可指定记住我。
     * <p>记住我会话使用 remember-timeout（长效），普通会话使用 timeout。</p>
     *
     * @return 下发给客户端的凭证（opaque 模式即随机 token，jwt 模式为签名 JWT）
     */
    public String login(Object userId, String device, boolean rememberMe) {
        String uid = String.valueOf(userId);
        String randomToken = tokenGenerator.generate();
        long now = clock.getAsLong();
        long ttl = rememberMe ? rememberTimeoutMillis : timeoutMillis;
        AuthSession session = new AuthSession(randomToken, uid, device, now, now);
        session.setRememberMe(rememberMe);
        sessionDao.saveSession(session, ttl);

        TokenCodec codec = tokenCodec;
        String credential = codec.issue(session, randomToken);
        // 索引与墓碑作用于"下发的凭证"，保证踢人/顶号在两种凭证模式下语义一致
        sessionDao.addToUserIndex(uid, device, credential, now + ttl);
        evictOverflowSessions(uid, device, credential);
        return credential;
    }

    /**
     * 顶号超额会话：保留最新的 maxSessionsPerDevice 个旧会话（新凭证恒保留），
     * 超额的按登录时间从旧到新标记"被顶下线"。
     */
    private void evictOverflowSessions(String userId, String device, String currentCredential) {
        int max = maxSessionsFor(device);
        if (max < 0) {
            return;
        }
        TokenCodec codec = tokenCodec;
        List<AuthSession> sessions = new ArrayList<>();
        for (String credential : sessionDao.getUserTokens(userId, device)) {
            if (credential.equals(currentCredential)) {
                continue;
            }
            AuthSession session = codec.selfValidating()
                    ? codec.describe(credential)
                    : sessionDao.getSession(credential);
            if (session != null) {
                sessions.add(session);
            } else {
                // 清理索引中的脏条目
                sessionDao.removeFromUserIndex(userId, device, credential);
            }
        }
        if (sessions.size() < max) {
            return;
        }
        sessions.sort(Comparator.comparingLong(AuthSession::getLoginTime));
        int excess = sessions.size() - max + 1;
        for (int i = 0; i < excess; i++) {
            evictSession(sessions.get(i), NotLoginReason.BE_REPLACED);
            publishEvent(sessions.get(i).getUserId(), sessions.get(i).getToken(),
                    io.github.biglv666.authkit.event.AuthKitSessionEvent.Action.REPLACED);
        }
    }

    /** 会话上限：按设备覆盖优先，其次全局值 */
    private int maxSessionsFor(String device) {
        Integer override = deviceMaxSessions.get(device);
        return override != null ? override : maxSessionsPerDevice;
    }

    /** 驱逐一个会话：删会话（opaque）/ 写墓碑（统一）+ 清索引；reason 为 BE_REPLACED 或 KICKED_OUT，null=纯失效 */
    private void evictSession(AuthSession session, NotLoginReason reason) {
        TokenCodec codec = tokenCodec;
        String credential = session.getToken();
        if (!codec.selfValidating()) {
            sessionDao.deleteSession(credential);
        }
        if (reason != null) {
            sessionDao.markKicked(codec.keyOf(credential), reason, timeoutMillis);
        }
        sessionDao.removeFromUserIndex(session.getUserId(), session.getDevice(), credential);
    }

    /**
     * 登出当前请求的登录态（凭证从 {@link AuthContext} 获取），幂等。
     */
    public void logout() {
        String credential = AuthContext.getToken();
        if (credential != null) {
            logout(credential);
        }
    }

    /**
     * 登出指定凭证，幂等。JWT 模式下写 TOKEN_INVALID 墓碑（否则凭证在到期前仍有效）。
     */
    public void logout(String credential) {
        TokenCodec codec = tokenCodec;
        if (codec.selfValidating()) {
            sessionDao.markKicked(codec.keyOf(credential), NotLoginReason.TOKEN_INVALID, timeoutMillis);
            sessionDao.removeFromUserIndex(extractUserIdQuietly(credential), extractDeviceQuietly(credential), credential);
            publishEvent(extractUserIdQuietly(credential), credential,
                    io.github.biglv666.authkit.event.AuthKitSessionEvent.Action.LOGOUT);
            return;
        }
        AuthSession session = sessionDao.getSession(credential);
        if (session != null) {
            sessionDao.deleteSession(credential);
            sessionDao.removeFromUserIndex(session.getUserId(), session.getDevice(), credential);
            publishEvent(session.getUserId(), credential,
                    io.github.biglv666.authkit.event.AuthKitSessionEvent.Action.LOGOUT);
        }
    }

    /**
     * 踢人下线：按用户（可选设备）使其全部凭证失效，并写墓碑使旧端收到 KICKED_OUT 语义。幂等。
     *
     * @param device 设备标识；null 表示全部设备
     */
    public void kickout(Object userId, String device) {
        kickOrLogout(userId, device, NotLoginReason.KICKED_OUT);
    }

    /**
     * 强制下线（管理端使用）：不写 KICKED_OUT 墓碑，旧端收到 TOKEN_INVALID 语义。幂等。
     *
     * @param device 设备标识；null 表示全部设备
     */
    public void forceLogout(Object userId, String device) {
        kickOrLogout(userId, device, null);
    }

    private void kickOrLogout(Object userId, String device, NotLoginReason reason) {
        String uid = String.valueOf(userId);
        for (String credential : sessionDao.getUserTokens(uid, device)) {
            AuthSession session = tokenCodec.selfValidating()
                    ? tokenCodec.describe(credential)
                    : sessionDao.getSession(credential);
            if (session == null) {
                // 清理索引脏条目
                sessionDao.removeFromUserIndex(uid, device, credential);
                continue;
            }
            session.setToken(credential);
            evictSession(session, reason);
            io.github.biglv666.authkit.event.AuthKitSessionEvent.Action action =
                    reason == NotLoginReason.KICKED_OUT
                            ? io.github.biglv666.authkit.event.AuthKitSessionEvent.Action.KICKED_OUT
                            : io.github.biglv666.authkit.event.AuthKitSessionEvent.Action.FORCED_LOGOUT;
            publishEvent(session.getUserId(), credential, action);
        }
    }

    /**
     * 列出用户在线会话（管理端点使用）。索引脏条目自动跳过。
     *
     * @param device 设备标识；null 表示全部设备
     */
    public List<AuthSession> listSessions(Object userId, String device) {
        String uid = String.valueOf(userId);
        List<AuthSession> result = new ArrayList<>();
        for (String credential : sessionDao.getUserTokens(uid, device)) {
            AuthSession session = tokenCodec.selfValidating()
                    ? tokenCodec.describe(credential)
                    : sessionDao.getSession(credential);
            if (session != null) {
                session.setToken(credential);
                result.add(session);
            }
        }
        return result;
    }

    // ── 校验 ──

    /**
     * 校验指定凭证。
     * <p>opaque 模式：会话存在 → 未超活跃超时 → 推进活跃时间（滑动续期，不延长绝对有效期）。
     * jwt 模式：本地验签 + exp + 墓碑黑名单，不读会话、无滑动续期。</p>
     *
     * @return 校验通过后的会话数据（jwt 模式为凭证 claims 的轻量映射）
     */
    public AuthSession checkLogin(String credential) {
        if (credential == null || credential.isBlank()) {
            throw new NotLoginException(NotLoginReason.NO_TOKEN);
        }
        TokenCodec codec = tokenCodec;
        if (codec.selfValidating()) {
            codec.verify(credential);
            NotLoginReason kickReason = sessionDao.getKickReason(codec.keyOf(credential));
            if (kickReason != null) {
                throw new NotLoginException(kickReason);
            }
            AuthSession session = codec.describe(credential);
            if (session == null) {
                throw new NotLoginException(NotLoginReason.TOKEN_INVALID);
            }
            return session;
        }
        AuthSession session = sessionDao.getSession(credential);
        if (session == null) {
            // 会话不存在：优先查墓碑，区分"被踢/被顶"与普通失效
            NotLoginReason kickReason = sessionDao.getKickReason(credential);
            throw new NotLoginException(kickReason != null ? kickReason : NotLoginReason.TOKEN_INVALID);
        }
        long now = clock.getAsLong();
        if (activeTimeoutMillis > 0 && now - session.getLastActiveTime() > activeTimeoutMillis) {
            // 长期不活跃：主动清除会话与索引
            sessionDao.deleteSession(credential);
            sessionDao.removeFromUserIndex(session.getUserId(), session.getDevice(), credential);
            throw new NotLoginException(NotLoginReason.TOKEN_TIMEOUT);
        }
        // 滑动续期：仅推进活跃时间（绝对有效期在登录时一次确定，不随请求延长）
        session.setLastActiveTime(now);
        sessionDao.updateLastActiveTime(credential, now);
        return session;
    }

    /**
     * 校验当前请求上下文的登录态（凭证从 {@link AuthContext} 获取）。
     */
    public AuthSession checkLogin() {
        return checkLogin(AuthContext.getToken());
    }

    // ── 二级认证 ──

    /**
     * 开启当前用户的安全态：业务方自行验密成功后调用，
     * 之后 safe-duration 内 @RequireSafe 端点放行。
     *
     * @throws NotLoginException 未登录
     */
    public void openSafe() {
        SafeStore store = requireSafeStore();
        store.mark(requireUserId(), safeDurationMillis);
    }

    /**
     * 判断当前用户是否在安全态内。
     */
    public boolean isSafe() {
        String userId = AuthContext.getUserId();
        SafeStore store = safeStore;
        return userId != null && store != null && store.exists(userId);
    }

    /**
     * 判断指定用户是否在安全态内（拦截器使用，不依赖 ThreadLocal）。
     */
    public boolean isSafe(String userId) {
        SafeStore store = safeStore;
        return store != null && store.exists(userId);
    }

    /** 关闭当前用户的安全态（如敏感操作完成即失效），幂等 */
    public void closeSafe() {
        String userId = AuthContext.getUserId();
        SafeStore store = safeStore;
        if (userId != null && store != null) {
            store.clear(userId);
        }
    }

    /** 校验指定用户的二级认证状态，未通过抛 NotSafeException（拦截器使用） */
    public void checkSafe(String userId) {
        if (!isSafe(userId)) {
            throw new NotSafeException();
        }
    }

    private SafeStore requireSafeStore() {
        SafeStore store = safeStore;
        if (store == null) {
            throw new IllegalStateException("SafeStore 未装配");
        }
        return store;
    }

    // ── 权限/角色校验 ──

    /**
     * 校验当前用户是否拥有指定权限（单个）。
     *
     * @throws NotPermissionException 不具备该权限
     * @throws NotLoginException      未登录
     */
    public void checkPermission(String permission) {
        checkPermission(requireUserId(), permission);
    }

    /**
     * 校验指定用户是否拥有权限（拦截器使用，不依赖 ThreadLocal 上下文）。
     */
    public void checkPermission(String userId, String permission) {
        if (!loadPermissions(userId).contains(permission)) {
            throw new NotPermissionException(permission);
        }
    }

    /**
     * 校验当前用户是否满足权限列表（ALL=全部满足 / ANY=满足其一）。
     */
    public void checkPermissions(List<String> permissions, AuthMode mode) {
        checkPermissions(requireUserId(), permissions, mode);
    }

    /**
     * 校验指定用户是否满足权限列表（ALL=全部满足 / ANY=满足其一）。
     */
    public void checkPermissions(String userId, List<String> permissions, AuthMode mode) {
        if (permissions == null || permissions.isEmpty()) {
            return;
        }
        Set<String> owned = loadPermissions(userId);
        boolean pass = mode == AuthMode.ALL
                ? owned.containsAll(permissions)
                : permissions.stream().anyMatch(owned::contains);
        if (!pass) {
            throw new NotPermissionException(String.join(",", permissions));
        }
    }

    /**
     * 校验当前用户是否拥有指定角色（单个）。
     */
    public void checkRole(String role) {
        checkRole(requireUserId(), role);
    }

    /**
     * 校验指定用户是否拥有角色（拦截器使用，不依赖 ThreadLocal 上下文）。
     */
    public void checkRole(String userId, String role) {
        if (!loadRoles(userId).contains(role)) {
            throw new NotRoleException(role);
        }
    }

    /**
     * 校验当前用户是否满足角色列表（ALL=全部满足 / ANY=满足其一）。
     */
    public void checkRoles(List<String> roles, AuthMode mode) {
        checkRoles(requireUserId(), roles, mode);
    }

    /**
     * 校验指定用户是否满足角色列表（ALL=全部满足 / ANY=满足其一）。
     */
    public void checkRoles(String userId, List<String> roles, AuthMode mode) {
        if (roles == null || roles.isEmpty()) {
            return;
        }
        Set<String> owned = loadRoles(userId);
        boolean pass = mode == AuthMode.ALL
                ? owned.containsAll(roles)
                : roles.stream().anyMatch(owned::contains);
        if (!pass) {
            throw new NotRoleException(String.join(",", roles));
        }
    }

    /** 判断当前用户是否拥有权限（不抛异常版本） */
    public boolean hasPermission(String permission) {
        try {
            checkPermission(permission);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** 判断当前用户是否拥有角色（不抛异常版本） */
    public boolean hasRole(String role) {
        try {
            checkRole(role);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * 获取当前登录用户标识。
     *
     * @throws NotLoginException 未登录
     */
    public String getLoginId() {
        return requireUserId();
    }

    /**
     * 以 long 形式获取当前登录用户标识。
     */
    public long getLoginIdAsLong() {
        return Long.parseLong(requireUserId());
    }

    /**
     * 判断当前请求是否已登录（基于 ThreadLocal 上下文，不做存储层校验）。
     */
    public boolean isLogin() {
        return AuthContext.getUserId() != null;
    }

    /** 普通会话的绝对有效期（毫秒），OAuth2 服务器签发令牌时用于 expires_in */
    public long getTimeoutMillis() {
        return timeoutMillis;
    }

    private String requireUserId() {
        String userId = AuthContext.getUserId();
        if (userId == null) {
            throw new NotLoginException(NotLoginReason.NO_TOKEN);
        }
        return userId;
    }

    private Set<String> loadPermissions(String userId) {
        PermissionProvider provider = permissionProvider;
        if (provider == null) {
            // 未配置权限数据源时一律拒绝，避免静默放行
            throw new NotPermissionException("(未配置 PermissionProvider)");
        }
        return Objects.requireNonNullElse(provider.getPermissions(userId), Set.of());
    }

    private Set<String> loadRoles(String userId) {
        PermissionProvider provider = permissionProvider;
        if (provider == null) {
            throw new NotRoleException("(未配置 PermissionProvider)");
        }
        return Objects.requireNonNullElse(provider.getRoles(userId), Set.of());
    }

    private String extractUserIdQuietly(String credential) {
        AuthSession session = tokenCodec.describe(credential);
        return session == null ? null : session.getUserId();
    }

    private String extractDeviceQuietly(String credential) {
        AuthSession session = tokenCodec.describe(credential);
        return session == null ? null : session.getDevice();
    }
}
