package io.github.biglv666.authkit.token;

/**
 * 不透明凭证编解码（默认实现）：凭证即随机 token，所有方法走接口默认实现。
 */
public class OpaqueTokenCodec implements TokenCodec {

    @Override
    public boolean selfValidating() {
        return false;
    }
}
