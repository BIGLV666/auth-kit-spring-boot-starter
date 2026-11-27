package io.github.biglv666.authkit.dao;

import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskControlStore;
import io.github.biglv666.authkit.guard.RiskDecision;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * 基于内存的风控状态实现（无 Redis 时降级；仅适合单实例部署）。
 * <p>所有状态变更通过 {@link ConcurrentHashMap#compute} 按 key 串行化，保证 check 的原子性。</p>
 * <p>为避免攻击者用海量随机用户名撑爆堆内存：普通尝试状态使用较短 TTL，且每 1024 次检查
 * 惰性清理过期状态；状态总数超过上限时优先淘汰普通状态，其次淘汰已结束的风控历史，
 * 最后才在活跃风控数量超过硬上限时淘汰最早结束的活跃风控。清理通过
 * {@code computeIfPresent} 重新校验状态，避免删掉并发更新后的状态。</p>
 * <p>容量上限在并发下是尽力而为的，两次清理之间可能短暂超出。</p>
 */
public class InMemoryRiskControlStore implements RiskControlStore {

    private static final int DEFAULT_MAX_STATES = 100_000;
    private static final int SWEEP_MASK = 1023;
    private static final long MIN_SHORT_TTL_MILLIS = 60_000L;

    private static final class State {
        final Deque<Long> attempts = new ArrayDeque<>();
        int lockoutCount;
        long lockedUntil;
        long lastLockoutEnd;
        long lastTouch;
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private final AtomicInteger operations = new AtomicInteger();
    private final int maxStates;
    private final int hardMaxStates;

    public InMemoryRiskControlStore() {
        this(DEFAULT_MAX_STATES);
    }

    /** 测试用：可限制状态总数。 */
    InMemoryRiskControlStore(int maxStates) {
        if (maxStates <= 0) {
            throw new IllegalArgumentException("maxStates 必须大于 0");
        }
        this.maxStates = maxStates;
        this.hardMaxStates = maxStates > Integer.MAX_VALUE / 2 ? Integer.MAX_VALUE : maxStates * 2;
    }

    @Override
    public RiskDecision check(String key, RiskControlPolicy policy, long nowMillis) {
        if (policy.maxAttempts() <= 0) {
            return RiskDecision.allowed(0, 0);
        }
        RiskDecision[] result = new RiskDecision[1];
        states.compute(key, (k, old) -> {
            State state = activeOrNew(old, policy, nowMillis);
            state.lastTouch = nowMillis;

            if (state.lockedUntil > nowMillis) {
                result[0] = RiskDecision.locked(state.lockedUntil - nowMillis,
                        state.attempts.size(), state.lockoutCount);
                return state;
            }

            prune(state.attempts, nowMillis - policy.attemptWindowMillis());
            if (state.attempts.size() >= policy.maxAttempts()) {
                enterLockout(state, policy, nowMillis);
                result[0] = RiskDecision.locked(state.lockedUntil - nowMillis, 0, state.lockoutCount);
                return state;
            }

            state.attempts.addLast(nowMillis);
            while (state.attempts.size() > policy.maxAttempts()) {
                state.attempts.pollFirst();
            }
            result[0] = RiskDecision.allowed(state.attempts.size(), state.lockoutCount);
            return state;
        });

        if ((operations.incrementAndGet() & SWEEP_MASK) == 0) {
            sweep(nowMillis, policy);
        }
        return result[0];
    }

    @Override
    public void recordSuccess(String key, RiskControlPolicy policy, long nowMillis) {
        if (!policy.resetOnSuccess()) {
            return;
        }
        states.computeIfPresent(key, (k, state) -> {
            if (expired(state, policy, nowMillis)) {
                return null;
            }
            state.attempts.clear();
            state.lastTouch = nowMillis;
            return isEmpty(state) ? null : state;
        });
    }

    @Override
    public void clear(String key) {
        states.remove(key);
    }

    /** 测试/诊断用：当前保留的状态 key 数量。 */
    int stateCount() {
        return states.size();
    }

    private void enterLockout(State state, RiskControlPolicy policy, long nowMillis) {
        boolean consecutive = state.lastLockoutEnd > 0
                && nowMillis - state.lastLockoutEnd <= policy.lockoutResetIntervalMillis();
        state.lockoutCount = consecutive ? state.lockoutCount + 1 : 1;
        long duration = policy.lockoutDurationMillis(state.lockoutCount);
        state.lockedUntil = nowMillis + duration;
        state.lastLockoutEnd = state.lockedUntil;
        state.attempts.clear();
    }

    private State activeOrNew(State old, RiskControlPolicy policy, long nowMillis) {
        if (old == null || expired(old, policy, nowMillis)) {
            return new State();
        }
        return old;
    }

    private boolean expired(State state, RiskControlPolicy policy, long nowMillis) {
        return nowMillis - state.lastTouch > stateTtl(state, policy);
    }

    /**
     * 未触发过风控的普通尝试状态只需覆盖尝试窗口，避免随机用户名长期占用内存；
     * 一旦有风控历史，则必须保留到静默期结束之后。
     */
    private long stateTtl(State state, RiskControlPolicy policy) {
        if (isProtected(state)) {
            return policy.effectiveStateTtlMillis();
        }
        return Math.max(policy.attemptWindowMillis() * 2, MIN_SHORT_TTL_MILLIS);
    }

    private boolean isProtected(State state) {
        return state.lockoutCount > 0 || state.lockedUntil > 0 || state.lastLockoutEnd > 0;
    }

    private boolean isEmpty(State state) {
        return state.attempts.isEmpty()
                && state.lockoutCount == 0
                && state.lockedUntil == 0
                && state.lastLockoutEnd == 0;
    }

    private void prune(Deque<Long> attempts, long cutoff) {
        while (!attempts.isEmpty() && attempts.peekFirst() <= cutoff) {
            attempts.pollFirst();
        }
    }

    /** 清理过期状态并执行容量上限；包内可见以便测试直接触发。 */
    void sweep(long nowMillis, RiskControlPolicy policy) {
        // 1. 过期状态：快照筛选 + computeIfPresent 重新校验，避免删掉并发刷新后的状态
        List<String> expiredKeys = new ArrayList<>();
        states.forEach((key, state) -> {
            if (expired(state, policy, nowMillis)) {
                expiredKeys.add(key);
            }
        });
        for (String key : expiredKeys) {
            states.computeIfPresent(key,
                    (k, state) -> expired(state, policy, nowMillis) ? null : state);
        }
        if (states.size() <= maxStates) {
            return;
        }

        // 2. 优先淘汰未触发过风控的普通状态
        evictWhere(state -> !isProtected(state), maxStates);
        if (states.size() <= maxStates) {
            return;
        }

        // 3. 其次淘汰风控已结束、只剩升级历史的状态
        evictWhere(state -> state.lockedUntil <= nowMillis, maxStates);
        if (states.size() <= maxStates) {
            return;
        }

        // 4. 最后兜底：活跃风控数量超过硬上限时，淘汰最早结束的活跃风控
        if (states.size() > hardMaxStates) {
            List<Map.Entry<String, Long>> active = new ArrayList<>();
            states.forEach((key, state) -> {
                if (state.lockedUntil > nowMillis) {
                    active.add(Map.entry(key, state.lockedUntil));
                }
            });
            active.sort(Map.Entry.comparingByValue());
            int toRemove = states.size() - hardMaxStates;
            for (int i = 0; i < toRemove && i < active.size(); i++) {
                states.computeIfPresent(active.get(i).getKey(),
                        (k, state) -> state.lockedUntil > nowMillis ? null : state);
            }
        }
    }

    private void evictWhere(Predicate<State> canEvict, int targetSize) {
        if (states.size() <= targetSize) {
            return;
        }
        List<String> candidates = new ArrayList<>();
        states.forEach((key, state) -> {
            if (canEvict.test(state)) {
                candidates.add(key);
            }
        });
        for (String key : candidates) {
            if (states.size() <= targetSize) {
                break;
            }
            states.computeIfPresent(key, (k, state) -> canEvict.test(state) ? null : state);
        }
    }
}
