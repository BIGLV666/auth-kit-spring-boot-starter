package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthSession;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * 基于内存的会话存储实现（无 Redis 时自动降级使用，仅适合本地开发/单实例部署）。
 * <p>所有过期数据在读路径上惰性清除，不做后台扫描；时间源可注入以便测试。</p>
 */
public class InMemorySessionDao implements SessionDao {

    /** 会话条目：会话数据 + 过期时间戳 */
    private record SessionEntry(AuthSession session, long expireAtMillis) {
    }

    /** 墓碑条目：踢出原因 + 过期时间戳 */
    private record KickEntry(NotLoginReason reason, long expireAtMillis) {
    }

    private final ConcurrentHashMap<String, SessionEntry> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, KickEntry> kickMarks = new ConcurrentHashMap<>();
    /** 反查索引：key = userId + ":" + device，value = token → 预期过期时间戳 */
    private final ConcurrentHashMap<String, Map<String, Long>> userIndex = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public InMemorySessionDao() {
        this(System::currentTimeMillis);
    }

    /** 允许注入时间源，供测试模拟时间推进 */
    public InMemorySessionDao(LongSupplier clock) {
        this.clock = clock;
    }

    @Override
    public void saveSession(AuthSession session, long timeoutMillis) {
        sessions.put(session.getToken(), new SessionEntry(session, clock.getAsLong() + timeoutMillis));
    }

    @Override
    public AuthSession getSession(String token) {
        SessionEntry entry = sessions.get(token);
        if (entry == null) {
            return null;
        }
        if (entry.expireAtMillis() <= clock.getAsLong()) {
            sessions.remove(token);
            return null;
        }
        return entry.session();
    }

    @Override
    public void deleteSession(String token) {
        sessions.remove(token);
    }

    @Override
    public void updateLastActiveTime(String token, long lastActiveTimeMillis) {
        sessions.computeIfPresent(token, (k, entry) -> {
            // 保持原过期时间不变，只推进活跃时间（滑动续期不延长绝对有效期）
            entry.session().setLastActiveTime(lastActiveTimeMillis);
            return entry;
        });
    }

    @Override
    public void markKicked(String token, NotLoginReason reason, long timeoutMillis) {
        kickMarks.put(token, new KickEntry(reason, clock.getAsLong() + timeoutMillis));
    }

    @Override
    public NotLoginReason getKickReason(String token) {
        KickEntry entry = kickMarks.get(token);
        if (entry == null) {
            return null;
        }
        if (entry.expireAtMillis() <= clock.getAsLong()) {
            kickMarks.remove(token);
            return null;
        }
        return entry.reason();
    }

    @Override
    public void addToUserIndex(String userId, String device, String token, long expireAtMillis) {
        userIndex.computeIfAbsent(indexKey(userId, device), k -> new ConcurrentHashMap<>())
                .put(token, expireAtMillis);
    }

    @Override
    public void removeFromUserIndex(String userId, String device, String token) {
        Map<String, Long> tokens = userIndex.get(indexKey(userId, device));
        if (tokens != null) {
            tokens.remove(token);
        }
        // 设备为空时（全量踢出）需要把其它设备的索引条目一并移除
        if (device == null) {
            userIndex.forEach((k, v) -> v.remove(token));
        }
    }

    @Override
    public Set<String> getUserTokens(String userId, String device) {
        long now = clock.getAsLong();
        Map<String, Map<String, Long>> candidates;
        if (device != null) {
            Map<String, Long> tokens = userIndex.get(indexKey(userId, device));
            candidates = tokens == null ? Map.of() : Map.of(indexKey(userId, device), tokens);
        } else {
            candidates = userIndex;
        }
        Set<String> result = ConcurrentHashMap.newKeySet();
        for (Map.Entry<String, Map<String, Long>> entry : candidates.entrySet()) {
            if (device == null && !entry.getKey().startsWith(userId + ":")) {
                continue;
            }
            entry.getValue().forEach((token, expireAt) -> {
                if (expireAt > now) {
                    result.add(token);
                } else {
                    // 惰性清理过期索引条目
                    entry.getValue().remove(token);
                }
            });
        }
        return result;
    }

    private String indexKey(String userId, String device) {
        return userId + ":" + Objects.requireNonNullElse(device, "");
    }
}
