package io.github.biglv666.authkit.core;

import io.github.biglv666.authkit.model.AuthMode;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.authkit.exception.NotRoleException;
import io.github.biglv666.authkit.model.AuthSession;
import io.github.biglv666.authkit.model.DeviceType;
import io.github.biglv666.authkit.spi.PermissionProvider;
import io.github.biglv666.authkit.token.TokenGenerator;
import io.github.biglv666.authkit.dao.SessionDao;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * 认证核心逻辑：签发、校验、续期、踢人、顶号、权限/角色校验。
 * <p>无状态于请求上下文；请求相关操作（当前登录人等）依赖
 * {@link AuthContext} 由拦截器填充。时间源可注入，便于测试模拟时间推进。</p>
 */
public class AuthManager {

    private final SessionDao sessionDao;
    private final TokenGenerator tokenGenerator;
    private final long timeoutMillis;
    private final long activeTimeoutMillis;
    private final int maxSessionsPerDevice;
    private final LongSupplier clock;
    private volatile PermissionProvider permissionProvider;

    public AuthManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                       long timeoutMillis, long activeTimeoutMillis, int maxSessionsPerDevice) {
        this(sessionDao, tokenGenerator, timeoutMillis, activeTimeoutMillis, maxSessionsPerDevice,
                System::currentTimeMillis);
    }

    /** 全参构造：时间源可注入，供测试模拟时间流逝 */
    public AuthManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                       long timeoutMillis, long activeTimeoutMillis, int maxSessionsPerDevice,
                       LongSupplier clock) {
        this.sessionDao = sessionDao;
        this.tokenGenerator = tokenGenerator;
        this.timeoutMillis = timeoutMillis;
        this.activeTimeoutMillis = activeTimeoutMillis;
        this.maxSessionsPerDevice = maxSessionsPerDevice;
        this.clock = clock;
    }

    /** 注入权限数据提供者（自动装配时可选注入，缺省则权限校验一律拒绝） */
    public void setPermissionProvider(PermissionProvider permissionProvider) {
        this.permissionProvider = permissionProvider;
    }

    // ── 登录态管理 ──

    /**
     * 登录并签发 token（默认设备 PC）。
     *
     * @param userId 用户标识
     * @return 新签发的 token
     */
    public String login(Object userId) {
        return login(userId, DeviceType.PC.getName());
    }

    /**
     * 登录并签发 token。
     *
     * @param userId     用户标识
     * @param deviceType 内置设备类型
     * @return 新签发的 token
     */
    public String login(Object userId, DeviceType deviceType) {
        return login(userId, deviceType.getName());
    }

    /**
     * 登录并签发 token；同端会话数超上限时按"最旧优先"顶号下线（标记 BE_REPLACED）。
     *
     * @param userId 用户标识
     * @param device 设备标识（自定义字符串）
     * @return 新签发的 token
     */
    public String login(Object userId, String device) {
        String uid = String.valueOf(userId);
        String token = tokenGenerator.generate();
        long now = clock.getAsLong();
        AuthSession session = new AuthSession(token, uid, device, now, now);
        sessionDao.saveSession(session, timeoutMillis);
        sessionDao.addToUserIndex(uid, device, token, now + timeoutMillis);
        evictOverflowSessions(uid, device, token);
        return token;
    }

    /**
     * 顶号超额会话：保留最新的 maxSessionsPerDevice 个旧会话（新 token 恒保留），
     * 超额的按登录时间从旧到新标记"被顶下线"。
     */
    private void evictOverflowSessions(String userId, String device, String currentToken) {
        if (maxSessionsPerDevice < 0) {
            return;
        }
        List<AuthSession> sessions = new ArrayList<>();
        for (String token : sessionDao.getUserTokens(userId, device)) {
            if (token.equals(currentToken)) {
                continue;
            }
            AuthSession session = sessionDao.getSession(token);
            if (session != null) {
                sessions.add(session);
            } else {
                // 清理索引中的脏条目
                sessionDao.removeFromUserIndex(userId, device, token);
            }
        }
        if (sessions.size() < maxSessionsPerDevice) {
            return;
        }
        sessions.sort(Comparator.comparingLong(AuthSession::getLoginTime));
        int excess = sessions.size() - maxSessionsPerDevice + 1;
        for (int i = 0; i < excess; i++) {
            AuthSession oldest = sessions.get(i);
            sessionDao.deleteSession(oldest.getToken());
            sessionDao.markKicked(oldest.getToken(), NotLoginReason.BE_REPLACED, timeoutMillis);
            sessionDao.removeFromUserIndex(oldest.getUserId(), oldest.getDevice(), oldest.getToken());
        }
    }

    /**
     * 登出当前请求的登录态（token 从 {@link AuthContext} 获取），幂等。
     */
    public void logout() {
        String token = AuthContext.getToken();
        if (token != null) {
            logout(token);
        }
    }

    /**
     * 登出指定 token（正常登出，不写墓碑），幂等。
     */
    public void logout(String token) {
        AuthSession session = sessionDao.getSession(token);
        if (session != null) {
            sessionDao.deleteSession(token);
            sessionDao.removeFromUserIndex(session.getUserId(), session.getDevice(), token);
        }
    }

    /**
     * 踢人下线：按用户（可选设备）删除其全部会话，并写墓碑使旧端收到 KICKED_OUT 语义。幂等。
     *
     * @param device 设备标识；null 表示全部设备
     */
    public void kickout(Object userId, String device) {
        kickOrLogout(userId, device, NotLoginReason.KICKED_OUT);
    }

    /**
     * 强制下线（管理端使用）：删除会话但不写墓碑，旧端收到 TOKEN_INVALID 语义。幂等。
     *
     * @param device 设备标识；null 表示全部设备
     */
    public void forceLogout(Object userId, String device) {
        kickOrLogout(userId, device, null);
    }

    private void kickOrLogout(Object userId, String device, NotLoginReason reason) {
        String uid = String.valueOf(userId);
        for (String token : sessionDao.getUserTokens(uid, device)) {
            AuthSession session = sessionDao.getSession(token);
            if (session == null) {
                // 清理索引脏条目
                sessionDao.removeFromUserIndex(uid, device, token);
                continue;
            }
            sessionDao.deleteSession(token);
            if (reason != null) {
                sessionDao.markKicked(token, reason, timeoutMillis);
            }
            sessionDao.removeFromUserIndex(session.getUserId(), session.getDevice(), token);
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
        for (String token : sessionDao.getUserTokens(uid, device)) {
            AuthSession session = sessionDao.getSession(token);
            if (session != null) {
                result.add(session);
            }
        }
        return result;
    }

    // ── 校验 ──

    /**
     * 校验并滑动续期指定 token。
     * <p>校验链：token 存在 → 未超活跃超时 → 更新最后活跃时间并重设 TTL。
     * 任一环节失败抛出带原因的 {@link NotLoginException}。</p>
     *
     * @return 校验通过后的会话数据
     */
    public AuthSession checkLogin(String token) {
        if (token == null || token.isBlank()) {
            throw new NotLoginException(NotLoginReason.NO_TOKEN);
        }
        AuthSession session = sessionDao.getSession(token);
        if (session == null) {
            // 会话不存在：优先查墓碑，区分"被踢/被顶"与普通失效
            NotLoginReason kickReason = sessionDao.getKickReason(token);
            throw new NotLoginException(kickReason != null ? kickReason : NotLoginReason.TOKEN_INVALID);
        }
        long now = clock.getAsLong();
        if (activeTimeoutMillis > 0 && now - session.getLastActiveTime() > activeTimeoutMillis) {
            // 长期不活跃：主动清除会话与索引
            sessionDao.deleteSession(token);
            sessionDao.removeFromUserIndex(session.getUserId(), session.getDevice(), token);
            throw new NotLoginException(NotLoginReason.TOKEN_TIMEOUT);
        }
        // 滑动续期：仅推进活跃时间（绝对有效期在登录时一次确定，不随请求延长）
        session.setLastActiveTime(now);
        sessionDao.updateLastActiveTime(token, now);
        return session;
    }

    /**
     * 校验当前请求上下文的登录态（token 从 {@link AuthContext} 获取）。
     */
    public AuthSession checkLogin() {
        return checkLogin(AuthContext.getToken());
    }

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
     * 判断当前请求是否已登录（基于 ThreadLocal 上下文，不做 Redis 校验）。
     */
    public boolean isLogin() {
        return AuthContext.getUserId() != null;
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
}
