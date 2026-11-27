package io.github.biglv666.authkit.webcommon;

import io.github.biglv666.authkit.exception.LoginLockedException;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.authkit.exception.NotRoleException;
import io.github.biglv666.authkit.exception.NotSafeException;
import io.github.biglv666.webcommon.config.HttpStatusMode;
import io.github.biglv666.webcommon.config.WebCommonProperties;
import io.github.biglv666.webcommon.result.Result;
import io.github.biglv666.webcommon.result.ResultCode;
import io.github.biglv666.webcommon.web.HttpStatusCodeResolver;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * web-common 适配层：类路径存在 web-common 时注册，把 auth-kit 异常映射为统一 Result 格式。
 * <p>优先级高于 web-common 的 GlobalExceptionHandler，业务代码零 try-catch。</p>
 *
 * <p>与 web-common 0.3.0 / 0.5.0 均兼容：</p>
 * <ul>
 *   <li>{@code web-common.http-status-mode=SEMANTIC} 时同步设置语义化 HTTP 状态码
 *       （默认 ALWAYS_200 保持 HTTP 200）；</li>
 *   <li>{@code web-common.trace-id.enabled=true} 时把 MDC 中的 traceId 写入错误 Result
 *       （0.5.0 才有的能力，通过 {@link WebCommonTraceIdSupport} 能力探测，0.3.0 自动跳过）。</li>
 * </ul>
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthKitWebCommonExceptionHandler {

    private final String kickedOutMessage;
    private final WebCommonProperties webCommonProperties;

    public AuthKitWebCommonExceptionHandler(String kickedOutMessage) {
        this(kickedOutMessage, null);
    }

    public AuthKitWebCommonExceptionHandler(String kickedOutMessage, WebCommonProperties webCommonProperties) {
        this.kickedOutMessage = kickedOutMessage;
        this.webCommonProperties = webCommonProperties;
    }

    /** 未登录/被踢/被顶/过期 → UNAUTHORIZED(40100)；被顶下线使用可配置文案 */
    @ExceptionHandler(NotLoginException.class)
    public Result<Void> handleNotLogin(NotLoginException e, HttpServletResponse response) {
        String message = e.getReason() == NotLoginReason.BE_REPLACED
                ? kickedOutMessage
                : e.getMessage();
        return fail(response, ResultCode.UNAUTHORIZED.getCode(), message);
    }

    /** 无权限 → FORBIDDEN(40300) */
    @ExceptionHandler(NotPermissionException.class)
    public Result<Void> handleNotPermission(NotPermissionException e, HttpServletResponse response) {
        return fail(response, ResultCode.FORBIDDEN.getCode(), e.getMessage());
    }

    /** 未通过二级认证 → FORBIDDEN(40300)，前端引导重新验密 */
    @ExceptionHandler(NotSafeException.class)
    public Result<Void> handleNotSafe(NotSafeException e, HttpServletResponse response) {
        return fail(response, ResultCode.FORBIDDEN.getCode(), e.getMessage());
    }

    /** 缺角色 → FORBIDDEN(40300) */
    @ExceptionHandler(NotRoleException.class)
    public Result<Void> handleNotRole(NotRoleException e, HttpServletResponse response) {
        return fail(response, ResultCode.FORBIDDEN.getCode(), e.getMessage());
    }

    /** 登录锁定 → UNAUTHORIZED(40100)，带剩余时间提示 */
    @ExceptionHandler(LoginLockedException.class)
    public Result<Void> handleLocked(LoginLockedException e, HttpServletResponse response) {
        return fail(response, ResultCode.UNAUTHORIZED.getCode(), e.getMessage());
    }

    private Result<Void> fail(HttpServletResponse response, int code, String message) {
        Result<Void> result = Result.fail(code, message);
        if (webCommonProperties != null
                && webCommonProperties.getHttpStatusMode() == HttpStatusMode.SEMANTIC) {
            response.setStatus(HttpStatusCodeResolver.resolve(code));
        }
        WebCommonTraceIdSupport.apply(webCommonProperties, result);
        return result;
    }
}
