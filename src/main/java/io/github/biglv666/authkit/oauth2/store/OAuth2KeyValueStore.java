package io.github.biglv666.authkit.oauth2.store;

/**
 * OAuth2 短时键值存储 SPI：授权码、刷新令牌、防 CSRF state 共用同一套 KV 抽象。
 * <p>值由调用方编码（组件内使用 URL 编码 + 换行分隔的紧凑格式）。
 * 内置 Redis（多实例共享，生产默认）与内存（降级/测试）实现。</p>
 */
public interface OAuth2KeyValueStore {

    /**
     * 写入键值。
     *
     * @param key         键（组件内已带业务前缀）
     * @param value       值
     * @param ttlMillis   过期时长（毫秒）
     */
    void put(String key, String value, long ttlMillis);

    /**
     * 读取值（不删除）。
     *
     * @return 值；不存在或已过期返回 null
     */
    String get(String key);

    /**
     * 读取并删除（单次消费语义，授权码必须用）。
     *
     * @return 值；不存在或已过期返回 null
     */
    String remove(String key);

    /** 删除键，幂等 */
    void delete(String key);
}
