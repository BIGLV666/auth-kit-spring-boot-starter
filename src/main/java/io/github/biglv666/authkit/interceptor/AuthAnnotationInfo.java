package io.github.biglv666.authkit.interceptor;

import io.github.biglv666.authkit.annotation.AuthIgnore;
import io.github.biglv666.authkit.annotation.RequireLogin;
import io.github.biglv666.authkit.annotation.RequirePermission;
import io.github.biglv666.authkit.annotation.RequireRole;
import io.github.biglv666.authkit.model.AuthMode;

import java.util.List;

/**
 * 鉴权注解解析结果缓存条目：HandlerMethod 的注解元数据在首次请求时解析，
 * 之后命中本地缓存，避免每次请求反射。
 */
public class AuthAnnotationInfo {

    /** 规则：一组权限码/角色码 + 校验模式 */
    public record Rule(List<String> values, AuthMode mode) {
    }

    private final boolean ignore;
    private final boolean classRequireLogin;
    private final boolean methodRequireLogin;
    private final Rule classPermission;
    private final Rule methodPermission;
    private final Rule classRole;
    private final Rule methodRole;

    public AuthAnnotationInfo(boolean ignore, boolean classRequireLogin, boolean methodRequireLogin,
                              Rule classPermission, Rule methodPermission, Rule classRole, Rule methodRole) {
        this.ignore = ignore;
        this.classRequireLogin = classRequireLogin;
        this.methodRequireLogin = methodRequireLogin;
        this.classPermission = classPermission;
        this.methodPermission = methodPermission;
        this.classRole = classRole;
        this.methodRole = methodRole;
    }

    /** 是否短路一切校验（仅方法级 @AuthIgnore） */
    public boolean isIgnore() {
        return ignore;
    }

    /** 是否需要执行登录校验（显式注解或任何权限/角色规则隐含） */
    public boolean isRequireAuth() {
        return classRequireLogin || methodRequireLogin
                || classPermission != null || methodPermission != null
                || classRole != null || methodRole != null;
    }

    public Rule getClassPermission() {
        return classPermission;
    }

    public Rule getMethodPermission() {
        return methodPermission;
    }

    public Rule getClassRole() {
        return classRole;
    }

    public Rule getMethodRole() {
        return methodRole;
    }

    /** 从注解解析规则；未标注返回 null */
    static Rule toRule(RequirePermission annotation) {
        if (annotation == null) {
            return null;
        }
        return new Rule(List.of(annotation.value()), annotation.mode());
    }

    static Rule toRule(RequireRole annotation) {
        if (annotation == null) {
            return null;
        }
        return new Rule(List.of(annotation.value()), annotation.mode());
    }

    static boolean hasLogin(RequireLogin annotation) {
        return annotation != null;
    }

    static boolean hasIgnore(AuthIgnore annotation) {
        return annotation != null;
    }
}
