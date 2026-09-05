package io.github.biglv666.authkit.annotation;

import io.github.biglv666.authkit.model.AuthMode;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求角色：标注在方法或类上，隐含登录校验。
 * <p>叠加语义同 {@link RequirePermission}：类级 + 方法级取"与"关系。</p>
 */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {

    /** 所需角色标识列表 */
    String[] value();

    /** 校验模式：ALL=全部满足（默认），ANY=满足其一 */
    AuthMode mode() default AuthMode.ALL;
}
