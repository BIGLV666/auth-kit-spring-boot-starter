package io.github.biglv666.authkit.crypto;

import io.github.biglv666.authkit.spi.PasswordEncoder;

/**
 * BCrypt 密码编码适配器：将 spring-security-crypto 的 BCrypt 实现适配到 auth-kit 的
 * {@link PasswordEncoder} SPI。仅在类路径存在 spring-security-crypto 时由自动装配创建，
 * 组件本身不向使用方传递该依赖。
 */
public class BCryptPasswordEncoderAdapter implements PasswordEncoder {

    private final org.springframework.security.crypto.password.PasswordEncoder delegate =
            new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();

    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegate.matches(rawPassword, encodedPassword);
    }
}
