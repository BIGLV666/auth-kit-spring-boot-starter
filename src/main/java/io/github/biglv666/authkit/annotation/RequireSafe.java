package io.github.biglv666.authkit.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求二级认证：标注在敏感操作（改密、支付、注销等）上，请求须在二级认证有效期内
 * （业务方验密后调用 {@code AuthKit.openSafe()} 开启，默认 5 分钟），
 * 否则抛 NotSafeException（403 语义 + 专用提示）。
 * <p>隐含登录校验。类级 + 方法级同时存在时都需满足。</p>
 */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireSafe {
}
