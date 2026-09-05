package io.github.biglv666.authkit.dao;

/**
 * 登录失败计数存储 SPI：与 SessionDao 分离，便于单独替换计数策略。
 * <p>内置内存实现（本地开发降级）与 Redis 实现（生产默认）。</p>
 */
public interface AttemptStore {

    /**
     * 计数自增；首次自增时设置过期时间（固定窗口）。
     *
     * @param key           计数 key（已含前缀）
     * @param ttlMillis     过期时长（毫秒）
     * @return 自增后的计数值
     */
    long incr(String key, long ttlMillis);

    /**
     * 读取当前计数值，不存在返回 0。
     */
    long get(String key);

    /**
     * 清除计数（登录成功或解锁时调用），幂等。
     */
    void clear(String key);
}
