package io.github.biglv666.authkit.token;

import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.model.AuthSession;

/**
 * 凭证编解码 SPI：决定"下发给客户端的凭证"与"服务端存储/校验"之间的关系。
 *
 * <ul>
 *   <li>opaque（默认）：凭证即随机 token，自校验关闭，校验走会话读取——全功能；</li>
 *   <li>jwt：凭证为签名 JWT，自校验开启，校验路径 = 本地验签 + 墓碑黑名单，
 *       省掉每次请求的会话读，但失去滑动续期与实时活跃数据（代价见 DESIGN.md）。</li>
 * </ul>
 * <p>两种模式下，用户索引与墓碑都作用于"下发的凭证"（{@link #issue} 的返回值），
 * 因此踢人/顶号/强制下线语义在两种模式下保持一致。</p>
 */
public interface TokenCodec {

    /** 是否自校验模式：true 时校验路径跳过会话读取，改查墓碑黑名单 */
    default boolean selfValidating() {
        return false;
    }

    /**
     * 登录时把内部随机 token 包装为最终下发的凭证。
     *
     * @param session     会话数据（含 userId/device/loginTime）
     * @param randomToken 内部随机 token（opaque 模式即凭证本身）
     * @return 下发给客户端的凭证
     */
    default String issue(AuthSession session, String randomToken) {
        return randomToken;
    }

    /**
     * 校验凭证本身（JWT：验签 + 有效期校验）。
     *
     * @throws NotLoginException TOKEN_INVALID（格式非法/验签失败）或 TOKEN_TIMEOUT（已过期）
     */
    default String verify(String credential) {
        return credential;
    }

    /**
     * 自校验模式下从凭证解出会话描述（userId/device/loginTime）；不支持的实现返回 null。
     * 不校验签名，仅解析——调用方必须先经过 {@link #verify}。
     */
    default AuthSession describe(String credential) {
        return null;
    }

    /** 凭证在墓碑/索引中的 key（opaque：原 token；JWT：摘要，避免超长 key） */
    default String keyOf(String credential) {
        return credential;
    }
}
