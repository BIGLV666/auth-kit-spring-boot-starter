package io.github.biglv666.authkit.dao;

/**
 * 二级认证状态存储 SPI：记录"某用户已通过安全验证"的短期标记。
 * <p>内置 Redis 实现（生产默认，多实例共享）与内存实现（降级）。</p>
 */
public interface SafeStore {

    /**
     * 标记用户已通过二级认证。
     *
     * @param userId    用户标识
     * @param ttlMillis 有效时长（毫秒）
     */
    void mark(String userId, long ttlMillis);

    /**
     * 查询用户是否在二级认证有效期内。
     */
    boolean exists(String userId);

    /**
     * 清除二级认证标记（主动关闭安全态），幂等。
     */
    void clear(String userId);
}
