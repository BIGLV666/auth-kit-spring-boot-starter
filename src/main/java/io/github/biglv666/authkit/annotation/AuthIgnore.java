package io.github.biglv666.authkit.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 忽略鉴权：标注在方法上，短路该方法的一切 auth-kit 校验（等价匿名放行）。
 * <p><b>安全警告</b>：仅用于健康检查、公开文档等确需匿名访问的端点；
 * 仅方法级生效，不支持类级，防止整类误放行。</p>
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthIgnore {
}
