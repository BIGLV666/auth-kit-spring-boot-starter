package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 基于 Redis 的会话存储实现（生产默认）。
 * <p>key 设计：</p>
 * <ul>
 *   <li>{@code {prefix}:token:{token}} — Hash，会话真源，TTL 即会话有效期</li>
 *   <li>{@code {prefix}:kick:{token}} — String，被踢墓碑，值为踢出原因</li>
 *   <li>{@code {prefix}:user:{userId}} — ZSet，反查索引；member = device|token，score = 预期过期时间戳</li>
 * </ul>
 * <p>索引读取时按 score 惰性清理过期条目，容忍脏数据；设备标识中不要使用 "|" 字符。</p>
 */
public class RedisSessionDao implements SessionDao {

    private static final String TOKEN_KEY = ":token:";
    private static final String KICK_KEY = ":kick:";
    private static final String USER_KEY = ":user:";
    private static final String INDEX_SEPARATOR = "|";

    /**
     * 原子续期脚本：仅当会话 key 仍存在时更新 lastActiveTime。
     * <p>不能拆成 hasKey + HSET：两步之间 key 若恰好过期，HSET 会重建一个<b>无 TTL</b> 的 Hash，
     * 使会话逃脱绝对有效期。Lua 在 Redis 单线程内原子执行，杜绝该窗口。</p>
     */
    private static final RedisScript<Long> TOUCH_LAST_ACTIVE_SCRIPT = new DefaultRedisScript<>(
            "if redis.call('exists', KEYS[1]) == 1 then "
                    + "redis.call('hset', KEYS[1], 'lastActiveTime', ARGV[1]); return 1 end return 0",
            Long.class);

    private final StringRedisTemplate redis;
    private final String prefix;

    public RedisSessionDao(StringRedisTemplate redis, String keyPrefix) {
        this.redis = redis;
        this.prefix = keyPrefix;
    }

    @Override
    public void saveSession(AuthSession session, long timeoutMillis) {
        String key = prefix + TOKEN_KEY + session.getToken();
        Map<String, String> fields = new HashMap<>(8);
        fields.put("token", session.getToken());
        fields.put("userId", session.getUserId());
        fields.put("device", session.getDevice());
        fields.put("loginTime", String.valueOf(session.getLoginTime()));
        fields.put("lastActiveTime", String.valueOf(session.getLastActiveTime()));
        fields.put("rememberMe", String.valueOf(session.isRememberMe()));
        fields.put("expireAt", String.valueOf(session.getExpireAt()));
        redis.opsForHash().putAll(key, fields);
        redis.expire(key, java.time.Duration.ofMillis(timeoutMillis));
    }

    @Override
    public AuthSession getSession(String token) {
        Map<Object, Object> fields = redis.opsForHash().entries(prefix + TOKEN_KEY + token);
        if (fields.isEmpty()) {
            return null;
        }
        AuthSession session = new AuthSession();
        session.setToken((String) fields.get("token"));
        session.setUserId((String) fields.get("userId"));
        session.setDevice((String) fields.get("device"));
        session.setLoginTime(Long.parseLong((String) fields.get("loginTime")));
        session.setLastActiveTime(Long.parseLong((String) fields.get("lastActiveTime")));
        Object remember = fields.get("rememberMe");
        session.setRememberMe(remember != null && Boolean.parseBoolean((String) remember));
        // 旧版本写入的会话没有 expireAt 字段，保持 0 以走兼容路径
        Object expireAt = fields.get("expireAt");
        session.setExpireAt(expireAt == null ? 0 : Long.parseLong((String) expireAt));
        return session;
    }

    @Override
    public void deleteSession(String token) {
        redis.delete(prefix + TOKEN_KEY + token);
    }

    @Override
    public void updateLastActiveTime(String token, long lastActiveTimeMillis) {
        // 原子脚本：会话不存在时静默忽略，存在时只改字段、不碰 TTL（绝对有效期不延长）
        redis.execute(TOUCH_LAST_ACTIVE_SCRIPT,
                List.of(prefix + TOKEN_KEY + token),
                String.valueOf(lastActiveTimeMillis));
    }

    @Override
    public void markKicked(String token, NotLoginReason reason, long timeoutMillis) {
        redis.opsForValue().set(prefix + KICK_KEY + token, reason.name(),
                java.time.Duration.ofMillis(timeoutMillis));
    }

    @Override
    public NotLoginReason getKickReason(String token) {
        String value = redis.opsForValue().get(prefix + KICK_KEY + token);
        if (value == null) {
            return null;
        }
        try {
            return NotLoginReason.valueOf(value);
        } catch (IllegalArgumentException e) {
            // 未知原因视为已失效，不中断校验流程
            return NotLoginReason.KICKED_OUT;
        }
    }

    @Override
    public void addToUserIndex(String userId, String device, String token, long expireAtMillis) {
        redis.opsForZSet().add(prefix + USER_KEY + userId, indexMember(device, token), expireAtMillis);
    }

    @Override
    public void removeFromUserIndex(String userId, String device, String token) {
        String userKey = prefix + USER_KEY + userId;
        if (device != null) {
            redis.opsForZSet().remove(userKey, indexMember(device, token));
            return;
        }
        // device=null 表示全端清理：逐个匹配 "device|token" 后缀（member 中 token 唯一）
        Set<String> members = redis.opsForZSet().range(userKey, 0, -1);
        if (members == null || members.isEmpty()) {
            return;
        }
        String suffix = INDEX_SEPARATOR + token;
        Object[] toRemove = members.stream().filter(m -> m.endsWith(suffix)).toArray();
        if (toRemove.length > 0) {
            redis.opsForZSet().remove(userKey, toRemove);
        }
    }

    @Override
    public Set<String> getUserTokens(String userId, String device) {
        String userKey = prefix + USER_KEY + userId;
        long now = System.currentTimeMillis();
        // 惰性清理已过期的索引条目
        redis.opsForZSet().removeRangeByScore(userKey, 0, now);
        Set<ZSetOperations.TypedTuple<String>> tuples =
                redis.opsForZSet().rangeWithScores(userKey, 0, Long.MAX_VALUE);
        Set<String> tokens = new HashSet<>();
        if (tuples == null) {
            return tokens;
        }
        for (ZSetOperations.TypedTuple<String> tuple : tuples) {
            String member = tuple.getValue();
            int sep = member.indexOf(INDEX_SEPARATOR);
            if (sep <= 0) {
                continue;
            }
            String memberDevice = member.substring(0, sep);
            String memberToken = member.substring(sep + 1);
            if (device == null || device.equals(memberDevice)) {
                tokens.add(memberToken);
            }
        }
        return tokens;
    }

    private String indexMember(String device, String token) {
        return device + INDEX_SEPARATOR + token;
    }
}
