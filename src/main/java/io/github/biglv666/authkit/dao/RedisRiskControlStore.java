package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskControlStore;
import io.github.biglv666.authkit.guard.RiskDecision;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;
import java.util.Objects;

/**
 * 基于 Redis 的风控状态实现（生产默认）。
 * <p>状态存在单个 HASH 中：attempts（JSON 数组）、lockoutCount、lockedUntil、lastLockoutEnd。
 * check 通过 Lua 脚本一次完成读取、清理、判定、升级与写回，保证多实例下的原子性。</p>
 * <p>未触发风控的普通尝试状态使用较短 TTL（max(2×尝试窗口, 1m)），只有带风控历史的状态
 * 才保留到 {@code state-ttl}，避免随机用户名登录扫描长期占用 Redis 内存。</p>
 * <p>时间戳由调用方传入（与内存实现一致），部署时要求各实例时钟同步。</p>
 */
public class RedisRiskControlStore implements RiskControlStore {

    private static final String CHECK_LUA = """
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local maxAttempts = tonumber(ARGV[3])
            local resetInterval = tonumber(ARGV[4])
            local durations = cjson.decode(ARGV[5])
            local stateTtl = tonumber(ARGV[6])
            local shortTtl = tonumber(ARGV[7])

            local raw = redis.call('HMGET', key, 'attempts', 'lockoutCount', 'lockedUntil', 'lastLockoutEnd')
            local attempts = {}
            if raw[1] and raw[1] ~= '' then
              local ok, decoded = pcall(cjson.decode, raw[1])
              if ok and type(decoded) == 'table' then attempts = decoded end
            end
            local lockoutCount = tonumber(raw[2]) or 0
            local lockedUntil = tonumber(raw[3]) or 0
            local lastLockoutEnd = tonumber(raw[4]) or 0

            if lockedUntil > now then
              return tostring(0) .. '|' .. tostring(lockedUntil - now) .. '|' .. tostring(#attempts) .. '|' .. tostring(lockoutCount)
            end

            local cutoff = now - window
            local kept = {}
            for i = 1, #attempts do
              local t = tonumber(attempts[i])
              if t and t > cutoff then kept[#kept + 1] = t end
            end
            attempts = kept

            if #attempts >= maxAttempts then
              local consecutive = lastLockoutEnd > 0 and (now - lastLockoutEnd) <= resetInterval
              if consecutive then
                lockoutCount = lockoutCount + 1
              else
                lockoutCount = 1
              end
              local idx = lockoutCount
              if idx > #durations then idx = #durations end
              if idx < 1 then idx = 1 end
              local duration = tonumber(durations[idx])
              lockedUntil = now + duration
              lastLockoutEnd = lockedUntil
              redis.call('HSET', key,
                'attempts', '[]',
                'lockoutCount', lockoutCount,
                'lockedUntil', lockedUntil,
                'lastLockoutEnd', lastLockoutEnd)
              redis.call('PEXPIRE', key, stateTtl)
              return tostring(0) .. '|' .. tostring(duration) .. '|0|' .. tostring(lockoutCount)
            end

            attempts[#attempts + 1] = now
            while #attempts > maxAttempts do
              table.remove(attempts, 1)
            end
            redis.call('HSET', key,
              'attempts', cjson.encode(attempts),
              'lockoutCount', lockoutCount,
              'lockedUntil', lockedUntil,
              'lastLockoutEnd', lastLockoutEnd)
            local ttl = stateTtl
            if lockoutCount == 0 and lastLockoutEnd == 0 then
              ttl = shortTtl
            end
            redis.call('PEXPIRE', key, ttl)
            return tostring(1) .. '|0|' .. tostring(#attempts) .. '|' .. tostring(lockoutCount)
            """;

    private static final String SUCCESS_LUA = """
            local key = KEYS[1]
            local resetOnSuccess = tonumber(ARGV[1])
            local stateTtl = tonumber(ARGV[2])
            if resetOnSuccess == 0 then return 0 end
            if redis.call('EXISTS', key) == 0 then return 0 end
            local lockoutCount = tonumber(redis.call('HGET', key, 'lockoutCount')) or 0
            local lockedUntil = tonumber(redis.call('HGET', key, 'lockedUntil')) or 0
            local lastLockoutEnd = tonumber(redis.call('HGET', key, 'lastLockoutEnd')) or 0
            if lockoutCount == 0 and lockedUntil == 0 and lastLockoutEnd == 0 then
              redis.call('DEL', key)
            else
              redis.call('HSET', key, 'attempts', '[]')
              redis.call('PEXPIRE', key, stateTtl)
            end
            return 1
            """;

    private static final DefaultRedisScript<String> CHECK_SCRIPT =
            new DefaultRedisScript<>(CHECK_LUA, String.class);
    private static final DefaultRedisScript<Long> SUCCESS_SCRIPT =
            new DefaultRedisScript<>(SUCCESS_LUA, Long.class);

    private final StringRedisTemplate redis;

    public RedisRiskControlStore(StringRedisTemplate redis) {
        this.redis = Objects.requireNonNull(redis, "redis");
    }

    @Override
    public RiskDecision check(String key, RiskControlPolicy policy, long nowMillis) {
        if (policy.maxAttempts() <= 0) {
            return RiskDecision.allowed(0, 0);
        }
        String result = redis.execute(CHECK_SCRIPT, List.of(key),
                Long.toString(nowMillis),
                Long.toString(policy.attemptWindowMillis()),
                Integer.toString(policy.maxAttempts()),
                Long.toString(policy.lockoutResetIntervalMillis()),
                durationsJson(policy),
                Long.toString(policy.effectiveStateTtlMillis()),
                Long.toString(shortTtlMillis(policy)));
        return parse(result);
    }

    @Override
    public void recordSuccess(String key, RiskControlPolicy policy, long nowMillis) {
        redis.execute(SUCCESS_SCRIPT, List.of(key),
                policy.resetOnSuccess() ? "1" : "0",
                Long.toString(policy.effectiveStateTtlMillis()));
    }

    @Override
    public void clear(String key) {
        redis.delete(key);
    }

    private static RiskDecision parse(String result) {
        if (result == null) {
            throw new IllegalStateException("auth-kit 风控脚本返回空结果");
        }
        String[] parts = result.split("\\|", -1);
        if (parts.length != 4) {
            throw new IllegalStateException("auth-kit 风控脚本返回格式非法：" + result);
        }
        boolean allowed = "1".equals(parts[0]);
        long retryAfter = Long.parseLong(parts[1]);
        int attemptCount = Integer.parseInt(parts[2]);
        int lockoutCount = Integer.parseInt(parts[3]);
        return allowed
                ? RiskDecision.allowed(attemptCount, lockoutCount)
                : RiskDecision.locked(retryAfter, attemptCount, lockoutCount);
    }

    /** 未触发风控的普通尝试状态只需覆盖尝试窗口，避免随机用户名长期占用 Redis 内存。 */
    private static long shortTtlMillis(RiskControlPolicy policy) {
        return Math.max(policy.attemptWindowMillis() * 2, 60_000L);
    }

    private static String durationsJson(RiskControlPolicy policy) {
        List<Long> durations = policy.lockoutDurationsMillis();
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < durations.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(durations.get(i));
        }
        return json.append(']').toString();
    }
}
