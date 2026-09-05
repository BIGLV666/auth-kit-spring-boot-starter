package io.github.biglv666.authkit.itest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * JWT 模式端到端集成测试：凭证为 HS256 签名 JWT，校验走验签 + 墓碑。
 */
@SpringBootTest(classes = {TestApp.class, TestController.class},
        properties = {"auth-kit.token.mode=jwt",
                "auth-kit.token.jwt-secret=itest-jwt-secret-0123456789",
                "auth-kit.whitelist[0]=/whitelisted/**",
                "auth-kit.whitelist[1]=/login"})
@AutoConfigureMockMvc
class AuthKitJwtModeIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private String login(String userId) throws Exception {
        MvcResult result = mockMvc.perform(post("/login").param("userId", userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        int i = body.indexOf("\"token\":\"");
        int start = i + "\"token\":\"".length();
        return body.substring(start, body.indexOf('"', start));
    }

    @Test
    void credentialIsJwtAndPassesValidation() throws Exception {
        String token = login("10001");
        assertNotEquals(-1, token.indexOf('.'), "JWT 模式凭证应含签名分隔符");
        mockMvc.perform(get("/need/login").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0));
    }

    @Test
    void tamperedJwtIsRejected() throws Exception {
        String token = login("10001");
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        mockMvc.perform(get("/need/login").header("Authorization", "Bearer " + tampered))
                .andExpect(jsonPath("$.code").value(40100));
    }

    @Test
    void reloginReplacesOldJwt() throws Exception {
        String old = login("10001");
        login("10001");
        mockMvc.perform(get("/need/login").header("Authorization", "Bearer " + old))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(40100))
                .andExpect(jsonPath("$.message").value("您已在其他设备登录"));
    }

    @Test
    void safeFlowEndToEnd() throws Exception {
        String token = login("10001");
        // 未开启二级认证 → 403
        mockMvc.perform(post("/safe/change-password").header("Authorization", "Bearer " + token))
                .andExpect(jsonPath("$.code").value(40300));
        // 开启后放行
        mockMvc.perform(post("/safe/open").header("Authorization", "Bearer " + token))
                .andExpect(jsonPath("$.code").value(0));
        mockMvc.perform(post("/safe/change-password").header("Authorization", "Bearer " + token))
                .andExpect(jsonPath("$.code").value(0));
        assertTrue(true);
    }
}
