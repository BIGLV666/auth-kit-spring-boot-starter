package io.github.biglv666.authkit.oauth2;

import io.github.biglv666.authkit.itest.TestApp;
import io.github.biglv666.authkit.itest.TestController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * OAuth2 授权服务器端到端测试：登录 → authorize → code → token →
 * 用 access_token 访问受保护接口（同一会话体系）→ refresh 轮换。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = {
                "auth-kit.oauth2.server.enabled=true",
                "auth-kit.oauth2.server.clients.app1.client-secret=secret-app1",
                "auth-kit.oauth2.server.clients.app1.redirect-uris[0]=https://app1.example/cb",
                "auth-kit.oauth2.server.clients.app1.scopes[0]=profile"})
@AutoConfigureMockMvc
class OAuth2ServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void fullAuthorizationCodeFlow() throws Exception {
        // 1. 用户登录
        String userToken = login("10001");

        // 2. 授权：已登录 → 302 回调携带 code
        MvcResult authResult = mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code").param("client_id", "app1")
                        .param("redirect_uri", "https://app1.example/cb")
                        .param("scope", "profile").param("state", "st-1")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String redirected = authResult.getResponse().getRedirectedUrl();
        assertNotNull(redirected);
        assertTrue(redirected.startsWith("https://app1.example/cb?code="), "应回跳回调地址");
        assertTrue(redirected.contains("state=st-1"), "state 应原样回传");
        String code = extractParam(redirected, "code");

        // 3. 换取令牌
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "app1").param("client_secret", "secret-app1")
                        .param("code", code).param("redirect_uri", "https://app1.example/cb"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.access_token").isNotEmpty())
                .andExpect(jsonPath("$.data.refresh_token").isNotEmpty())
                .andExpect(jsonPath("$.data.token_type").value("Bearer"))
                .andReturn();
        String body = tokenResult.getResponse().getContentAsString();
        String accessToken = extractJsonField(body, "access_token");
        String refreshToken = extractJsonField(body, "refresh_token");

        // 4. access_token 即 auth-kit 会话凭证：直接访问受保护接口
        mockMvc.perform(get("/need/login").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0));

        // 5. 授权码一次性：重放 → invalid_grant（HTTP 400）
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "app1").param("client_secret", "secret-app1")
                        .param("code", code).param("redirect_uri", "https://app1.example/cb"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("invalid_grant"));

        // 6. 刷新令牌轮换：旧 refresh 用后即废
        MvcResult refreshResult = mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", "app1").param("client_secret", "secret-app1")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.access_token").isNotEmpty())
                .andReturn();
        String newRefresh = extractJsonField(refreshResult.getResponse().getContentAsString(), "refresh_token");
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token")
                        .param("client_id", "app1").param("client_secret", "secret-app1")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("invalid_grant"));
        assertTrue(!newRefresh.equals(refreshToken), "refresh_token 应轮换");
    }

    @Test
    void wrongClientSecretRejected() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "app1").param("client_secret", "wrong")
                        .param("code", "whatever").param("redirect_uri", "https://app1.example/cb"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("invalid_client"));
    }

    @Test
    void unregisteredRedirectUriRejected() throws Exception {
        String userToken = login("10001");
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code").param("client_id", "app1")
                        .param("redirect_uri", "https://evil.example/cb")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("invalid_client"));
    }

    @Test
    void scopeBeyondRegistrationRejected() throws Exception {
        String userToken = login("10001");
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code").param("client_id", "app1")
                        .param("redirect_uri", "https://app1.example/cb")
                        .param("scope", "profile admin:write")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("invalid_scope"));
    }

    /**
     * 回归：RFC 6749 要求 authorize 带 redirect_uri 时 token 请求原样带回；
     * 客户端漏带该参数时必须是 invalid_grant(400)，而不是 NPE(500)。
     */
    @Test
    void missingRedirectUriReturnsInvalidGrant() throws Exception {
        String userToken = login("10001");
        MvcResult authResult = mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code").param("client_id", "app1")
                        .param("redirect_uri", "https://app1.example/cb")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String code = extractParam(authResult.getResponse().getRedirectedUrl(), "code");
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "app1").param("client_secret", "secret-app1")
                        .param("code", code))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("invalid_grant"));
    }

    @Test
    void unsupportedGrantTypeRejected() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "password")
                        .param("client_id", "app1").param("client_secret", "secret-app1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.error").value("unsupported_grant_type"));
    }

    @Test
    void anonymousAuthorizeRedirectsToLoginPage() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code").param("client_id", "app1")
                        .param("redirect_uri", "https://app1.example/cb"))
                .andExpect(status().is3xxRedirection());
    }

    private String login(String userId) throws Exception {
        MvcResult result = mockMvc.perform(post("/login").param("userId", userId))
                .andExpect(status().isOk()).andReturn();
        return extractJsonField(result.getResponse().getContentAsString(), "token");
    }

    private static String extractParam(String url, String param) {
        Matcher m = Pattern.compile(param + "=([^&]+)").matcher(url);
        assertTrue(m.find(), "应含参数 " + param);
        return URLDecoder.decode(m.group(1), StandardCharsets.UTF_8);
    }

    private static String extractJsonField(String body, String field) {
        Matcher m = Pattern.compile("\"" + field + "\":\"([^\"]+)\"").matcher(body);
        assertTrue(m.find(), "应含字段 " + field);
        return m.group(1);
    }
}
