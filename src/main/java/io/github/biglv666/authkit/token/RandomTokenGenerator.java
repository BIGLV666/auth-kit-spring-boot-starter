package io.github.biglv666.authkit.token;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 默认 token 生成实现：SecureRandom 熵源 + Base64URL 编码的随机不透明 token。
 * <p>默认 64 字符（约 384 bit 熵），不可预测、无业务含义。</p>
 */
public class RandomTokenGenerator implements TokenGenerator {

    private final SecureRandom random = new SecureRandom();
    private final int length;

    public RandomTokenGenerator() {
        this(64);
    }

    /**
     * @param length token 字符长度（Base64URL 字符集，无填充无符号）
     */
    public RandomTokenGenerator(int length) {
        this.length = length;
    }

    @Override
    public String generate() {
        // base64url 每 4 字符对应 3 字节，多取 1 字节保证截取后仍够长
        byte[] bytes = new byte[length * 3 / 4 + 1];
        random.nextBytes(bytes);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return encoded.substring(0, length);
    }
}
