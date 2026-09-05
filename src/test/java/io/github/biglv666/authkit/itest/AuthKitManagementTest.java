package io.github.biglv666.authkit.itest;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.model.DeviceType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 管理端点集成测试：静态令牌鉴权（开/关两态）、在线会话查询、强制下线。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = {"auth-kit.management.enabled=true",
                "auth-kit.management.auth-token=test-secret",
                "auth-kit.management.base-path=/auth-kit",
                "auth-kit.whitelist[0]=/whitelisted/**"})
@AutoConfigureMockMvc
class AuthKitManagementTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void requiresStaticToken() throws Exception {
        AuthKit.login(10001, DeviceType.APP);
        // 无令牌 → 401；错误令牌 → 401
        mockMvc.perform(get("/auth-kit/online").param("userId", "10001"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/auth-kit/online").param("userId", "10001")
                        .header("X-Auth-Kit-Token", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listsAndForceLogsOutSessions() throws Exception {
        String token = AuthKit.login(10001, DeviceType.APP);
        mockMvc.perform(get("/auth-kit/online").param("userId", "10001")
                        .header("X-Auth-Kit-Token", "test-secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].userId").value("10001"))
                .andExpect(jsonPath("$.data[0].device").value("APP"))
                .andExpect(jsonPath("$.data[0].token").value(org.hamcrest.Matchers.startsWith(token.substring(0, 8))));
        // token 脱敏
        // 强制下线后原 token 失效（TOKEN_INVALID，无墓碑）
        mockMvc.perform(delete("/auth-kit/online/10001")
                        .header("X-Auth-Kit-Token", "test-secret"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("\"success\":true")));
        mockMvc.perform(get("/auth-kit/online").param("userId", "10001")
                        .header("X-Auth-Kit-Token", "test-secret"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("[]")));
    }

    @Test
    void nonManagementPathsBypassFilter() throws Exception {
        // 管理过滤器只拦 basePath 前缀，其他路径不受影响
        mockMvc.perform(get("/whitelisted/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("pong")));
    }
}
