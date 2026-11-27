package io.github.biglv666.authkit.observability;

import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.event.AuthKitSessionEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 默认审计日志实现：把认证审计/会话事件写到独立 logger（{@code auth-kit.audit}），
 * 便于单独配置脱敏、落盘或转发。
 *
 * <p><b>绝不记录 token/密码</b>：会话事件只记录 action/userId，不记录 credential。
 * 业务可注册自己的监听器替换本实现（{@code @ConditionalOnMissingBean}）。</p>
 */
public class AuthKitAuditLogger {

    private static final Logger log = LoggerFactory.getLogger("auth-kit.audit");

    public void onAudit(AuthKitAuditEvent event) {
        if (event == null) {
            return;
        }
        log.info("action={} identifier={} device={} reason={}",
                event.getAction(), event.getIdentifier(), event.getDevice(), event.getReason());
    }

    public void onSession(AuthKitSessionEvent event) {
        if (event == null) {
            return;
        }
        // 注意：不要记录 event.getCredential()（token）
        log.info("session-action={} userId={}", event.getAction(), event.getUserId());
    }
}
