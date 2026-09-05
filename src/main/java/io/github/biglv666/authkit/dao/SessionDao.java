package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;

import java.util.Set;

/**
 * 会话存储 SPI：会话数据访问的唯一抽象层。
 * <p>内置两个实现：{@link InMemorySessionDao}（无 Redis 降级）与
 * {@link RedisSessionDao}（生产默认）；业务方可注册自己的 Bean 全量替换。</p>
 * <p>契约约定：</p>
 * <ul>
 *   <li>token 会话 key 是唯一真源；用户反查索引允许脏读，实现方需容忍并惰性清理过期条目</li>
 *   <li>被踢/被顶会话先删 token 会话，再写"墓碑"记录踢出原因，供校验时返回专用错误语义</li>
 *   <li>所有方法对不存在的 key 应静默容错（幂等），不得抛出异常</li>
 * </ul>
 */
public interface SessionDao {

    /**
     * 保存或覆盖会话，并设置过期时间（滑动续期即以新的过期时间重复调用此方法）。
     *
     * @param session       会话数据
     * @param timeoutMillis 过期时长（毫秒）
     */
    void saveSession(AuthSession session, long timeoutMillis);

    /**
     * 按 token 读取会话。
     *
     * @param token 登录凭证
     * @return 会话数据；不存在或已过期返回 null
     */
    AuthSession getSession(String token);

    /**
     * 删除会话（登出、踢人时调用），幂等。
     *
     * @param token 登录凭证
     */
    void deleteSession(String token);

    /**
     * 仅更新最后活跃时间（滑动续期），<b>不得</b>重置会话的过期时间——
     * 会话过期时间在登录时由 timeout 一次性确定（绝对有效期），活跃度由独立判定。
     * 会话不存在时静默忽略。
     *
     * @param token               登录凭证
     * @param lastActiveTimeMillis 最后活跃时间戳（毫秒）
     */
    void updateLastActiveTime(String token, long lastActiveTimeMillis);

    /**
     * 写入"被踢下线"墓碑记录：token 会话已删除后，校验时可据此返回专用错误语义。
     *
     * @param token         已删除的 token
     * @param reason        踢出原因（KICKED_OUT / BE_REPLACED）
     * @param timeoutMillis 墓碑保留时长（毫秒），应与会话有效期一致
     */
    void markKicked(String token, NotLoginReason reason, long timeoutMillis);

    /**
     * 查询 token 的墓碑记录。
     *
     * @return 踢出原因；无墓碑或已过期返回 null
     */
    NotLoginReason getKickReason(String token);

    /**
     * 添加用户反查索引（userId+device → token），用于踢人、顶号与在线会话管理。
     *
     * @param expireAtMillis token 预期过期时间戳（毫秒），供实现方惰性清理脏数据
     */
    void addToUserIndex(String userId, String device, String token, long expireAtMillis);

    /**
     * 移除用户反查索引条目，幂等。
     */
    void removeFromUserIndex(String userId, String device, String token);

    /**
     * 查询用户在指定设备（或全部设备）下的有效 token 集合。
     * <p>允许返回已过期/已删除 token 的脏数据，调用方以 token 会话为准。</p>
     *
     * @param device 设备标识；null 表示全部设备
     */
    Set<String> getUserTokens(String userId, String device);
}
