package io.github.biglv666.authkit.guard;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 风控策略参数校验与档位计算。
 */
class RiskControlPolicyTest {

    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60L * MINUTE;
    private static final long DAY = 24L * HOUR;

    private static RiskControlPolicy valid() {
        return new RiskControlPolicy(5 * MINUTE, 5,
                List.of(5 * MINUTE, 15 * MINUTE, HOUR, 6 * HOUR, DAY),
                6 * HOUR, 7 * DAY, true);
    }

    @Test
    void lockoutDurationFollowsScheduleAndCapsAtLast() {
        RiskControlPolicy policy = valid();
        assertEquals(5 * MINUTE, policy.lockoutDurationMillis(1));
        assertEquals(15 * MINUTE, policy.lockoutDurationMillis(2));
        assertEquals(HOUR, policy.lockoutDurationMillis(3));
        assertEquals(6 * HOUR, policy.lockoutDurationMillis(4));
        assertEquals(DAY, policy.lockoutDurationMillis(5));
        assertEquals(DAY, policy.lockoutDurationMillis(6));
        assertEquals(DAY, policy.lockoutDurationMillis(99));
        assertEquals(5 * MINUTE, policy.lockoutDurationMillis(0));
        assertEquals(5 * MINUTE, policy.lockoutDurationMillis(-1));
    }

    @Test
    void effectiveTtlCoversLongestLockoutPlusResetAndWindow() {
        assertEquals(7 * DAY, valid().effectiveStateTtlMillis(), "7d 已覆盖 24h + 6h + 5m");

        RiskControlPolicy shortTtl = new RiskControlPolicy(5 * MINUTE, 5,
                List.of(DAY), 6 * HOUR, 1 * HOUR, true);
        long expected = DAY + 6 * HOUR + 5 * MINUTE;
        assertEquals(expected, shortTtl.effectiveStateTtlMillis(),
                "state-ttl 过短时必须被最长风控 + 静默期 + 窗口托底");
    }

    @Test
    void rejectsInvalidPolicy() {
        assertThrows(IllegalArgumentException.class,
                () -> new RiskControlPolicy(0, 5, List.of(MINUTE), 0, DAY, true));
        assertThrows(IllegalArgumentException.class,
                () -> new RiskControlPolicy(MINUTE, 5, List.of(), 0, DAY, true));
        assertThrows(IllegalArgumentException.class,
                () -> new RiskControlPolicy(MINUTE, 5, List.of(0L), 0, DAY, true));
        assertThrows(IllegalArgumentException.class,
                () -> new RiskControlPolicy(MINUTE, 5, List.of(15 * MINUTE, 5 * MINUTE), 0, DAY, true));
        assertThrows(IllegalArgumentException.class,
                () -> new RiskControlPolicy(MINUTE, 5, List.of(MINUTE), -1, DAY, true));
        assertThrows(IllegalArgumentException.class,
                () -> new RiskControlPolicy(MINUTE, 5, List.of(MINUTE), 0, 0, true));
    }

    @Test
    void negativeMaxAttemptsIsAllowedAsDisabled() {
        RiskControlPolicy policy = new RiskControlPolicy(MINUTE, -1, List.of(MINUTE), 0, DAY, true);
        assertEquals(-1, policy.maxAttempts(), "负值与 0 一样表示停用，不能在启动期报错");
    }

    @Test
    void copiesDurationsDefensively() {
        java.util.ArrayList<Long> durations = new java.util.ArrayList<>(List.of(MINUTE));
        RiskControlPolicy policy = new RiskControlPolicy(MINUTE, 5, durations, 0, DAY, true);
        durations.add(2 * MINUTE);
        assertEquals(1, policy.lockoutDurationsMillis().size());
        assertTrue(policy.lockoutDurationsMillis().contains(MINUTE));
    }
}
