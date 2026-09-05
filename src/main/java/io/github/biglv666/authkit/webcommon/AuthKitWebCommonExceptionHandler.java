package io.github.biglv666.authkit.webcommon;

import io.github.biglv666.authkit.exception.LoginLockedException;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.authkit.exception.NotRoleException;
import io.github.biglv666.authkit.exception.NotSafeException;
import io.github.biglv666.webcommon.result.Result;
import io.github.biglv666.webcommon.result.ResultCode;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * web-common 适配层：类路径存在 web-common 时注册，把 auth-kit 异常映射为统一 Result 格式。
 * <p>优先级高于 web-common 的 GlobalExceptionHandler，业务代码零 try-catch。</p>
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthKitWebCommonExceptionHandler {

    private final String kickedOutMessage;

    public AuthKitWebCommonExceptionHandler(String kickedOutMessage) {
        this.kickedOutMessage = kickedOutMessage;
    }

    /** 未登录/被踢/被顶/过期 → UNAUTHORIZED(40100)；被顶下线使用可配置文案 */
    @ExceptionHandler(NotLoginException.class)
    public Result<Void> handleNotLogin(NotLoginException e) {
        if (e.getReason() == NotLoginReason.BE_REPLACED) {
            return Result.fail(ResultCode.UNAUTHORIZED, kickedOutMessage);
        }
        return Result.fail(ResultCode.UNAUTHORIZED, e.getMessage());
    }

    /** 无权限 → FORBIDDEN(40300) */
    @ExceptionHandler(NotPermissionException.class)
    public Result<Void> handleNotPermission(NotPermissionException e) {
        return Result.fail(ResultCode.FORBIDDEN, e.getMessage());
    }

    /** 未通过二级认证 → FORBIDDEN(40300)，前端引导重新验密 */
    @ExceptionHandler(NotSafeException.class)
    public Result<Void> handleNotSafe(NotSafeException e) {
        return Result.fail(ResultCode.FORBIDDEN, e.getMessage());
    }

    /** 缺角色 → FORBIDDEN(40300) */
    @ExceptionHandler(NotRoleException.class)
    public Result<Void> handleNotRole(NotRoleException e) {
        return Result.fail(ResultCode.FORBIDDEN, e.getMessage());
    }

    /** 登录锁定 → UNAUTHORIZED(40100)，带剩余时间提示 */
    @ExceptionHandler(LoginLockedException.class)
    public Result<Void> handleLocked(LoginLockedException e) {
        return Result.fail(ResultCode.UNAUTHORIZED, e.getMessage());
    }
}
