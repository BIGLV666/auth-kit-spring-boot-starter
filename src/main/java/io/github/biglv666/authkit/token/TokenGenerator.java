package io.github.biglv666.authkit.token;

/**
 * Token 生成 SPI：决定登录凭证的形态。
 * <p>默认实现 {@link RandomTokenGenerator} 生成 64 位随机不透明 token；
 * 业务方可注册自己的 Bean（如带前缀的分段 token）全量替换。</p>
 */
public interface TokenGenerator {

    /**
     * 生成一个新的登录凭证。
     *
     * @return 全局唯一的 token 字符串
     */
    String generate();
}
