package io.github.biglv666.authkit.spi;

/**
 * 密码编码 SPI：业务方校验密码时使用，与 auth-kit 的认证流程解耦。
 * <p>类路径存在 spring-security-crypto 时，自动装配提供 BCrypt 默认实现；
 * 否则业务方需注册自己的 Bean。</p>
 */
public interface PasswordEncoder {

    /**
     * 对明文密码编码（通常用于注册/改密时生成入库密文）。
     *
     * @param rawPassword 明文密码
     * @return 编码后的密文（自带盐值）
     */
    String encode(CharSequence rawPassword);

    /**
     * 校验明文密码与密文是否匹配（登录时使用）。
     *
     * @param rawPassword    用户输入的明文密码
     * @param encodedPassword 库中存储的密文
     * @return 匹配返回 true
     */
    boolean matches(CharSequence rawPassword, String encodedPassword);
}
