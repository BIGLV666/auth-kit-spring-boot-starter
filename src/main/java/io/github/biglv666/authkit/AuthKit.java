package io.github.biglv666.authkit;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.model.AuthMode;
import io.github.biglv666.authkit.model.DeviceType;
import io.github.biglv666.authkit.model.AuthSession;

import java.util.List;

/**
 * auth-kit 统一门面：业务代码的静态入口。
 * <p>由自动装配初始化；在 Spring 容器启动前调用会抛出 {@link IllegalStateException}。</p>
 * <p>典型用法：</p>
 * <pre>{@code
 * // 业务方自行校验密码后调用
 * String token = AuthKit.login(userId, DeviceType.APP);
 * AuthKit.checkPermission("order:delete");
 * AuthKit.kickout(10001, DeviceType.APP);  // 踢人下线
 * }</pre>
 */
public final class AuthKit {

    private static volatile AuthManager authManager;

    private AuthKit() {
    }

    /** 由自动装配在容器启动时调用（组件内部使用，业务方请勿调用） */
    public static void init(AuthManager manager) {
        authManager = manager;
    }

    /** 获取核心管理器（供高级用法/测试使用） */
    public static AuthManager getAuthManager() {
        return requireManager();
    }

    private static AuthManager requireManager() {
        AuthManager manager = authManager;
        if (manager == null) {
            throw new IllegalStateException("auth-kit 尚未初始化：请确认应用以 Spring Boot 方式启动且 auth-kit.enabled 未被关闭");
        }
        return manager;
    }

    // ── 登录态 ──

    /** 登录并签发 token（默认设备 PC） */
    public static String login(Object userId) {
        return requireManager().login(userId);
    }

    /** 登录并签发 token，指定设备 */
    public static String login(Object userId, DeviceType deviceType) {
        return requireManager().login(userId, deviceType);
    }

    /** 登录并签发 token，指定自定义设备标识 */
    public static String login(Object userId, String device) {
        return requireManager().login(userId, device);
    }

    /** 登出当前请求的登录态 */
    public static void logout() {
        requireManager().logout();
    }

    /** 登出指定 token */
    public static void logout(String token) {
        requireManager().logout(token);
    }

    /**
     * 踢人下线（旧端请求将收到 KICKED_OUT 语义）。
     *
     * @param device 设备标识；null 表示全部设备
     */
    public static void kickout(Object userId, String device) {
        requireManager().kickout(userId, device);
    }

    /**
     * 踢人下线（内置设备类型）。
     */
    public static void kickout(Object userId, DeviceType deviceType) {
        requireManager().kickout(userId, deviceType.getName());
    }

    /** 强制下线（不写墓碑，旧端收到 TOKEN_INVALID 语义） */
    public static void forceLogout(Object userId, String device) {
        requireManager().forceLogout(userId, device);
    }

    /** 列出用户在线会话（device 为 null 表示全部设备） */
    public static List<AuthSession> listSessions(Object userId, String device) {
        return requireManager().listSessions(userId, device);
    }

    // ── 当前登录态查询 ──

    /** 当前登录用户标识，未登录抛 NotLoginException */
    public static String getLoginId() {
        return requireManager().getLoginId();
    }

    /** 当前登录用户标识（long 形式） */
    public static long getLoginIdAsLong() {
        return requireManager().getLoginIdAsLong();
    }

    /** 当前请求是否已登录（基于 ThreadLocal 上下文） */
    public static boolean isLogin() {
        return requireManager().isLogin();
    }

    // ── 校验 ──

    /** 校验当前请求登录态并滑动续期，失败抛 NotLoginException */
    public static void checkLogin() {
        requireManager().checkLogin();
    }

    /** 校验当前用户是否拥有指定权限 */
    public static void checkPermission(String permission) {
        requireManager().checkPermission(permission);
    }

    /** 校验当前用户是否满足权限列表（ALL/ANY 模式） */
    public static void checkPermissions(List<String> permissions, AuthMode mode) {
        requireManager().checkPermissions(permissions, mode);
    }

    /** 校验当前用户是否拥有指定角色 */
    public static void checkRole(String role) {
        requireManager().checkRole(role);
    }

    /** 校验当前用户是否满足角色列表（ALL/ANY 模式） */
    public static void checkRoles(List<String> roles, AuthMode mode) {
        requireManager().checkRoles(roles, mode);
    }

    /** 判断当前用户是否拥有权限（不抛异常） */
    public static boolean hasPermission(String permission) {
        return requireManager().hasPermission(permission);
    }

    /** 判断当前用户是否拥有角色（不抛异常） */
    public static boolean hasRole(String role) {
        return requireManager().hasRole(role);
    }

    /** 抛出未登录异常的便捷方法（业务自定义拦截场景使用） */
    public static void throwNotLogin(NotLoginException e) {
        throw e;
    }
}
