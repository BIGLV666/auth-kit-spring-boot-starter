package io.github.biglv666.authkit.webcommon;

import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.exception.NotPermissionException;
import io.github.biglv666.webcommon.config.HttpStatusMode;
import io.github.biglv666.webcommon.config.WebCommonProperties;
import io.github.biglv666.webcommon.result.Result;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * web-common 适配器：ALWAYS_200 默认契约不变；SEMANTIC 模式同步设置语义化状态码。
 */
class AuthKitWebCommonExceptionHandlerTest {

    private static WebCommonProperties properties(HttpStatusMode mode) {
        WebCommonProperties properties = new WebCommonProperties();
        properties.setHttpStatusMode(mode);
        return properties;
    }

    @Test
    void always200KeepsHttpStatus200() {
        AuthKitWebCommonExceptionHandler handler = new AuthKitWebCommonExceptionHandler(
                "被顶下线", properties(HttpStatusMode.ALWAYS_200));
        MockHttpServletResponse response = new MockHttpServletResponse();

        Result<Void> result = handler.handleNotLogin(
                new NotLoginException(NotLoginReason.TOKEN_INVALID), response);

        assertEquals(200, response.getStatus(), "默认 ALWAYS_200 不能改变 HTTP 状态");
        assertEquals(40100, result.getCode());
    }

    @Test
    void semanticModeMapsAuthErrorsTo400() {
        AuthKitWebCommonExceptionHandler handler = new AuthKitWebCommonExceptionHandler(
                "被顶下线", properties(HttpStatusMode.SEMANTIC));

        MockHttpServletResponse unauthorized = new MockHttpServletResponse();
        Result<Void> login = handler.handleNotLogin(
                new NotLoginException(NotLoginReason.TOKEN_INVALID), unauthorized);
        assertEquals(400, unauthorized.getStatus());
        assertEquals(40100, login.getCode());

        MockHttpServletResponse forbidden = new MockHttpServletResponse();
        Result<Void> permission = handler.handleNotPermission(
                new NotPermissionException("admin"), forbidden);
        assertEquals(400, forbidden.getStatus());
        assertEquals(40300, permission.getCode());
    }

    @Test
    void beReplacedUsesConfiguredMessage() {
        AuthKitWebCommonExceptionHandler handler = new AuthKitWebCommonExceptionHandler(
                "您已在其他设备登录", properties(HttpStatusMode.ALWAYS_200));

        Result<Void> result = handler.handleNotLogin(
                new NotLoginException(NotLoginReason.BE_REPLACED),
                new MockHttpServletResponse());

        assertEquals(40100, result.getCode());
        assertEquals("您已在其他设备登录", result.getMessage());
    }

    @Test
    void missingWebCommonPropertiesFallsBackTo200() {
        AuthKitWebCommonExceptionHandler handler = new AuthKitWebCommonExceptionHandler("被顶下线", null);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handleNotLogin(new NotLoginException(NotLoginReason.TOKEN_INVALID), response);

        assertEquals(200, response.getStatus());
    }
}
