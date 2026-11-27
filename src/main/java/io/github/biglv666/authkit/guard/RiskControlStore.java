package io.github.biglv666.authkit.guard;

/**
 * 风控状态存储 SPI（risk-control 模式）。
 * <p>{@link #check} 必须是针对同一 key 的原子操作：判断当前锁定、清理过期尝试、
 * 触发/升级风控、占用一次尝试额度必须一次完成，否则并发下会突破尝试上限或重复升级。</p>
 * <p>业务方注册同类型 Bean 即可全量替换默认的内存/Redis 实现。</p>
 */
public interface RiskControlStore {

    /**
     * 检查并占用一次尝试额度。
     *
     * @param key       风控标识（已含命名空间）
     * @param policy    风控策略
     * @param nowMillis 当前时间戳（毫秒）
     * @return 放行或锁定结果；锁定结果包含剩余毫秒数
     */
    RiskDecision check(String key, RiskControlPolicy policy, long nowMillis);

    /**
     * 登录成功：按策略清空尝试窗口。
     * <p>默认不清除连续风控次数，连续次数只由静默期或 {@link #clear} 重置。</p>
     */
    void recordSuccess(String key, RiskControlPolicy policy, long nowMillis);

    /** 管理端清除指定 key 的风控状态。 */
    void clear(String key);
}
