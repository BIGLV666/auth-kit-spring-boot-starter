package io.github.biglv666.authkit.oauth2;

import io.github.biglv666.authkit.itest.TestApp;
import io.github.biglv666.authkit.itest.TestController;
import io.github.biglv666.authkit.oauth2.client.IdentityProvider;
import io.github.biglv666.authkit.oauth2.client.OAuth2UserBinder;
import io.github.biglv666.authkit.oauth2.client.OAuth2UserProfile;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * OAuth2 客户端（第三方登录）端到端测试：自定义 IdentityProvider + 绑定器 → 回调签发本站会话。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class, OAuth2ClientIntegrationTest.FakeProviderConfig.class},
        properties = {"auth-kit.oauth2.client.enabled=true",
                "auth-kit.oauth2.client.success-redirect=/sso-done",
                "auth-kit.oauth2.client.providers.fake.redirect-uri=https://app.example/cb"})
@AutoConfigureMockMvc
class OAuth2ClientIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @TestConfiguration
    static class FakeProviderConfig {

        /** 假身份提供者：任何 code 都换出固定档案（验证流程编排，不验证平台协议） */
        @Bean
        public IdentityProvider fakeProvider() {
            return new IdentityProvider() {
                @Override
                public String name() {
                    return "fake";
                }

                @Override
                public String authorizeUrl(io.github.biglv666.authkit.oauth2.OAuth2Properties.ProviderConfig config,
                                           String redirectUri, String state) {
                    return "https://fake-idp.example/auth?state=" + state;
                }

                @Override
                public OAuth2UserProfile exchange(io.github.biglv666.authkit.oauth2.OAuth2Properties.ProviderConfig config,
                                                  String code, String redirectUri) {
                    return new OAuth2UserProfile("fake", "open-10001", "fakeuser", null, null, java.util.Map.of());
                }
            };
        }

        /** openId 以 "open-" 开头即绑定到对应数字 userId */
        @Bean
        public OAuth2UserBinder fakeBinder() {
            return profile -> profile.openId().startsWith("open-")
                    ? profile.openId().substring("open-".length()) : null;
        }
    }

    @Test
    void loginRedirectsToProviderWithState() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/login/fake"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String url = result.getResponse().getRedirectedUrl();
        assertNotNull(url);
        assertTrue(url.startsWith("https://fake-idp.example/auth?state="), "应跳平台授权页");
    }

    @Test
    void unknownProviderRejected() throws Exception {
        // web-common 统一包装：IllegalArgumentException → SYSTEM_ERROR(500)
        mockMvc.perform(get("/oauth2/login/nope"))
                .andExpect(jsonPath("$.code").value(500));
    }

    @Test
    void callbackIssuesLocalSessionAndRedirects() throws Exception {
        String state = obtainState();
        MvcResult result = mockMvc.perform(get("/oauth2/callback/fake")
                        .param("code", "any-code").param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String url = result.getResponse().getRedirectedUrl();
        assertNotNull(url);
        assertTrue(url.startsWith("/sso-done?token="), "应携带 token 跳落地页");
        String token = extractParam(url, "token");
        // 签发的是真正的 auth-kit 会话凭证（设备标识为 OAuth2:fake）
        mockMvc.perform(get("/me").header("Authorization", "Bearer " + token))
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data").value("10001:OAuth2:fake"));
    }

    @Test
    void callbackWithBadStateRejected() throws Exception {
        obtainState(); // 消耗一个合法 state
        mockMvc.perform(get("/oauth2/callback/fake")
                        .param("code", "any-code").param("state", "forged-state"))
                .andExpect(jsonPath("$.data.error").value("invalid_state"));
    }

    @Test
    void stateIsSingleUse() throws Exception {
        String state = obtainState();
        mockMvc.perform(get("/oauth2/callback/fake").param("code", "a").param("state", state))
                .andExpect(status().is3xxRedirection());
        // 同一 state 第二次使用 → invalid_state（防 CSRF 重放）
        mockMvc.perform(get("/oauth2/callback/fake").param("code", "a").param("state", state))
                .andExpect(jsonPath("$.data.error").value("invalid_state"));
    }

    private String obtainState() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/login/fake"))
                .andExpect(status().is3xxRedirection()).andReturn();
        return extractParam(result.getResponse().getRedirectedUrl(), "state");
    }

    private static String extractParam(String url, String param) {
        Matcher m = Pattern.compile("[?&]" + param + "=([^&]+)").matcher(url);
        assertTrue(m.find(), "应含参数 " + param);
        return URLDecoder.decode(m.group(1), StandardCharsets.UTF_8);
    }
}
