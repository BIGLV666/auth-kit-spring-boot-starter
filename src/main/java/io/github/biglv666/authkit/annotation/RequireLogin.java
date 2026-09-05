package io.github.biglv666.authkit.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求登录：标注在方法或类上，未登录请求将被拒绝。
 * <p>类级 + 方法级同时存在时二者都需满足（实际等价于单次登录校验）；
 * 标注了 {@link RequirePermission} / {@link RequireRole} 的方法隐含登录校验，无需重复标注。</p>
 */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireLogin {
}
