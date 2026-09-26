package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.AuthKit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端集成测试（内存会话实现 + web-common 统一 Result）。
 * <p>覆盖：白名单、软解析、注解体系（类/方法级叠加、ALL/ANY、@AuthIgnore）、
 * @CurrentUser、顶号下线、登出后失效。</p>
 */
@SpringBootTest(classes = {TestApp.class, TestController.class, ClassSecuredController.class},
        properties = {"auth-kit.whitelist[0]=/whitelisted/**",
                "auth-kit.whitelist[1]=/login"})
@AutoConfigureMockMvc
class AuthKitIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private String login(String userId, String device) throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                        .param("userId", userId).param("device", device))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        int i = body.indexOf("\"token\":\"");
        int start = i + "\"token\":\"".length();
        return body.substring(start, body.indexOf('"', start));
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }

    @Test
    void whitelistedPathPassesWithoutToken() throws Exception {
        mockMvc.perform(get("/whitelisted/ping"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data").value("pong"));
    }

    @Test
    void openEndpointSoftResolvesContext() throws Exception {
        // 无 token：放行，注入 null 用户
        mockMvc.perform(get("/open/me-optional"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("anonymous"));
        // 有 token：上下文可用
        String token = login("10001", "APP");
        mockMvc.perform(get("/open/me-optional").header("Authorization", bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("10001"));
    }

    @Test
    void requireLoginRejectsAnonymous() throws Exception {
        mockMvc.perform(get("/need/login"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(40100));
        String token = login("10001", "APP");
        mockMvc.perform(get("/need/login").header("Authorization", bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0));
    }

    @Test
    void businessPathContainingOauth2IsNotBypassed() throws Exception {
        // 回归：路径含 /oauth2/ 片段的业务端点曾被内置白名单误放行（鉴权绕过），必须保持强校验
        mockMvc.perform(get("/sso/oauth2/secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(40100));
        String token = login("10001", "APP");
        mockMvc.perform(get("/sso/oauth2/secret").header("Authorization", bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0));
    }

    @Test
    void permissionCheckedAgainstProvider() throws Exception {
        String token = login("10001", "APP");
        mockMvc.perform(get("/need/perm").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(0));
        // 20002 无任何权限
        String other = login("20002", "APP");
        mockMvc.perform(get("/need/perm").header("Authorization", bearer(other)))
                .andExpect(jsonPath("$.code").value(40300));
    }

    @Test
    void anyModePassesOnPartialMatch() throws Exception {
        String token = login("10001", "APP");
        mockMvc.perform(get("/need/perm-any").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(0));
        mockMvc.perform(get("/need/perm-denied-any").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(40300));
    }

    @Test
    void roleCheckedAgainstProvider() throws Exception {
        String token = login("10001", "APP");
        mockMvc.perform(get("/need/role").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(0));
    }

    @Test
    void currentUserInjectedWhenRequired() throws Exception {
        String token = login("10001", "APP");
        mockMvc.perform(get("/me").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.data").value("10001:APP"));
    }

    @Test
    void reloginReplacesOldSessionWithConfiguredMessage() throws Exception {
        String oldToken = login("10001", "APP");
        login("10001", "APP");
        mockMvc.perform(get("/need/login").header("Authorization", bearer(oldToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(40100))
                .andExpect(jsonPath("$.message").value("您已在其他设备登录"));
    }

    @Test
    void logoutInvalidatesToken() throws Exception {
        String token = login("10001", "APP");
        AuthKit.logout(token);
        mockMvc.perform(get("/need/login").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(40100))
                .andExpect(jsonPath("$.message").value("登录凭证无效"));
    }

    @Test
    void classLevelAnnotationEnforcedAndAuthIgnoreOverrides() throws Exception {
        // 类级 @RequirePermission("order:admin")：匿名 → 未登录；无权用户 → 403
        mockMvc.perform(get("/class/secured"))
                .andExpect(jsonPath("$.code").value(40100));
        String token = login("10001", "APP");
        mockMvc.perform(get("/class/secured").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(40300));
        // @AuthIgnore 覆盖类级注解：匿名放行
        mockMvc.perform(get("/class/ignored"))
                .andExpect(jsonPath("$.code").value(0));
        // 方法级 ANY：10001 无 order:admin 但组合 ANY 仍要求其一 → 403（两条都没有）
        mockMvc.perform(get("/class/any-of").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.code").value(40300));
    }

    @Test
    void malformedTokenIsRejected() throws Exception {
        mockMvc.perform(get("/need/login").header("Authorization", "Bearer fake-token-123"))
                .andExpect(jsonPath("$.code").value(40100));
        assertThat(true).isTrue();
    }
}
