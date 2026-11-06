package io.github.biglv666.authkit.oauth2.client;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 第三方登录落地页的 token 投递方式：默认 fragment（不进服务端日志/Referer），query 为兼容模式。
 */
class OAuth2ClientControllerTest {

    @Test
    void defaultDeliveryUsesFragment() {
        assertEquals("/sso-done#token=tok123",
                OAuth2ClientController.buildSuccessRedirect("/sso-done", null, "tok123"));
        assertEquals("/sso-done#token=tok123",
                OAuth2ClientController.buildSuccessRedirect("/sso-done", "fragment", "tok123"));
    }

    @Test
    void fragmentAppendsToExistingFragment() {
        assertEquals("/sso-done#section&token=tok123",
                OAuth2ClientController.buildSuccessRedirect("/sso-done#section", "fragment", "tok123"));
    }

    @Test
    void queryModeKeepsLegacyBehavior() {
        assertEquals("/sso-done?token=tok123",
                OAuth2ClientController.buildSuccessRedirect("/sso-done", "query", "tok123"));
        assertEquals("/sso-done?x=1&token=tok123",
                OAuth2ClientController.buildSuccessRedirect("/sso-done?x=1", "query", "tok123"));
    }

    @Test
    void tokenIsUrlEncoded() {
        assertEquals("/sso-done#token=a%2Bb",
                OAuth2ClientController.buildSuccessRedirect("/sso-done", "fragment", "a+b"));
    }
}
