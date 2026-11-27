package io.github.biglv666.authkit.observability;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.biglv666.authkit.event.AuthKitAuditEvent;
import io.github.biglv666.authkit.event.AuthKitSessionEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 审计日志不得泄露凭证：会话事件只记录 action/userId，不记录 credential。
 */
class AuthKitAuditLoggerTest {

    private final AuthKitAuditLogger auditLogger = new AuthKitAuditLogger();
    private Logger logger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void attach() {
        logger = (Logger) LoggerFactory.getLogger("auth-kit.audit");
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    @Test
    void auditEventContainsActionAndIdentifierButNeverToken() {
        auditLogger.onAudit(new AuthKitAuditEvent(
                AuthKitAuditEvent.Action.LOGIN_FAILURE, "alice", "PC", null));

        String output = rendered();
        assertTrue(output.contains("LOGIN_FAILURE"));
        assertTrue(output.contains("alice"));
    }

    @Test
    void sessionEventNeverLogsCredential() {
        auditLogger.onSession(new AuthKitSessionEvent(
                "u-1", "SUPER-SECRET-TOKEN", AuthKitSessionEvent.Action.LOGOUT));

        String output = rendered();
        assertTrue(output.contains("LOGOUT"));
        assertTrue(output.contains("u-1"));
        assertFalse(output.contains("SUPER-SECRET-TOKEN"), "审计日志不得出现 token");
    }

    private String rendered() {
        StringBuilder sb = new StringBuilder();
        for (ILoggingEvent event : appender.list) {
            sb.append(event.getFormattedMessage()).append('\n');
        }
        return sb.toString();
    }
}
