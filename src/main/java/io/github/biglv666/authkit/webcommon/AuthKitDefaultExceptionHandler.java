package io.github.biglv666.authkit.webcommon;

import io.github.biglv666.authkit.exception.LoginLockedException;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.authkit.exception.NotRoleException;
import io.github.biglv666.authkit.exception.NotSafeException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 原生异常映射（类路径无 web-common 时注册）：把 auth-kit 异常映射为标准 HTTP 状态码。
 * <p>401=未登录/被踢/过期/锁定，403=无权限/缺角色；响应体为简单的 {code, message}，
 * 不泄露内部细节。业务方注册自己的异常处理器 Bean 即可全量替换。</p>
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthKitDefaultExceptionHandler {

    /** 未登录/被踢/被顶/过期/锁定 → 401 */
    @ExceptionHandler({NotLoginException.class, LoginLockedException.class})
    public ResponseEntity<Map<String, Object>> handleUnauthorized(RuntimeException e) {
        return build(HttpStatus.UNAUTHORIZED, 401, e.getMessage());
    }

    /** 无权限/缺角色/未通过二级认证 → 403 */
    @ExceptionHandler({NotPermissionException.class, NotRoleException.class, NotSafeException.class})
    public ResponseEntity<Map<String, Object>> handleForbidden(RuntimeException e) {
        return build(HttpStatus.FORBIDDEN, 403, e.getMessage());
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, int code, String message) {
        Map<String, Object> body = new LinkedHashMap<>(2);
        body.put("code", code);
        body.put("message", message);
        return ResponseEntity.status(status).body(body);
    }
}
