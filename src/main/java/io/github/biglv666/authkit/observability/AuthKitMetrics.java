package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.event.AuthKitSessionEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.event.EventListener;

/**
 * auth-kit 指标采集（Micrometer，可选依赖）。
 *
 * <p>标签全部是有界枚举，<b>不使用 userId / token 等高基数值</b>，避免指标基数爆炸。
 * 通过 Spring 事件监听消费，不侵入认证主链路；监听异常由事件广播隔离。</p>
 *
 * <ul>
 *   <li>{@code authkit.login{outcome=success|failure|locked_out}}</li>
 *   <li>{@code authkit.guard.lockouts}</li>
 *   <li>{@code authkit.session.events{action=logout|kicked_out|forced_logout|replaced}}</li>
 * </ul>
 */
public class AuthKitMetrics {

    static final String LOGIN_METRIC = "authkit.login";
    static final String LOCKOUT_METRIC = "authkit.guard.lockouts";
    static final String SESSION_EVENT_METRIC = "authkit.session.events";

    private final MeterRegistry registry;

    public AuthKitMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    @EventListener
    public void onAudit(AuthKitAuditEvent event) {
        if (event == null || event.getAction() == null) {
            return;
        }
        String outcome = switch (event.getAction()) {
            case LOGIN_SUCCESS -> "success";
            case LOGIN_FAILURE -> "failure";
            case LOCKED_OUT -> "locked_out";
        };
        Counter.builder(LOGIN_METRIC)
                .description("auth-kit 登录结果")
                .tag("outcome", outcome)
                .register(registry)
                .increment();
        if (event.getAction() == AuthKitAuditEvent.Action.LOCKED_OUT) {
            Counter.builder(LOCKOUT_METRIC)
                    .description("auth-kit 触发登录锁定/风控次数")
                    .register(registry)
                    .increment();
        }
    }

    @EventListener
    public void onSession(AuthKitSessionEvent event) {
        if (event == null || event.getAction() == null) {
            return;
        }
        Counter.builder(SESSION_EVENT_METRIC)
                .description("auth-kit 会话生命周期事件")
                .tag("action", event.getAction().name().toLowerCase(java.util.Locale.ROOT))
                .register(registry)
                .increment();
    }
}
