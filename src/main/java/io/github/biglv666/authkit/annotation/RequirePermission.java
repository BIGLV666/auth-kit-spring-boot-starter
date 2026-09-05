package io.github.biglv666.authkit.annotation;

import io.github.biglv666.authkit.model.AuthMode;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求权限：标注在方法或类上，隐含登录校验。
 * <p>类级与方法级同时存在时取"与"关系：两级的规则都要满足
 * （各自按自己的 mode 判定），防止方法级注解意外放宽类级管控。</p>
 */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePermission {

    /** 所需权限码列表 */
    String[] value();

    /** 校验模式：ALL=全部满足（默认），ANY=满足其一 */
    AuthMode mode() default AuthMode.ALL;
}
