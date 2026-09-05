package io.github.biglv666.authkit.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 注入当前登录用户：标注在 Controller 方法参数（类型为 AuthUser）上，
 * 由参数解析器从认证上下文取值。
 * <pre>{@code
 * @GetMapping("/me")
 * public ProfileVO me(@CurrentUser AuthUser user) { ... }
 * }</pre>
 */
@Documented
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface CurrentUser {

    /** 未登录时是否抛出未登录异常；false 时注入 null（可用于"游客也可访问"的端点） */
    boolean required() default true;
}
