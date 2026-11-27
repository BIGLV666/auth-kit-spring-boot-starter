package io.github.biglv666.compat;

import io.github.biglv666.authkit.AuthKit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * web-common 0.5.0 的 SEMANTIC 状态码 + traceId 与 auth-kit 异常映射的兼容性。
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = CompatApp.class,
        properties = {
                "web-common.http-status-mode=SEMANTIC",
                "web-common.trace-id.enabled=true"
        })
class Boot4SemanticTraceCompatTest {

    @Value("${local.server.port}")
    private int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void semanticStatusAndTraceIdOnAuthErrors() throws Exception {
        String token = AuthKit.login("semantic-user", "PC");

        HttpResponse<String> success = get("/api/me", token);
        assertEquals(200, success.statusCode());
        assertNotNull(success.headers().firstValue("X-Trace-Id").orElse(null),
                "trace-id 过滤器应写入响应头");
        assertTrue(success.body().contains("\"traceId\":\""));
        assertTrue(success.body().contains("\"code\":0"));

        HttpResponse<String> anonymous = get("/api/me", null);
        assertEquals(400, anonymous.statusCode(), "SEMANTIC 模式 40100 应映射为 400");
        assertTrue(anonymous.body().contains("\"code\":40100"), anonymous.body());
        assertTrue(anonymous.body().contains("\"traceId\":\""),
                "auth-kit 错误 Result 也必须带 traceId: " + anonymous.body());

        HttpResponse<String> forbidden = get("/api/admin", token);
        assertEquals(400, forbidden.statusCode(), "SEMANTIC 模式 40300 应映射为 400");
        assertTrue(forbidden.body().contains("\"code\":40300"), forbidden.body());
        assertTrue(forbidden.body().contains("\"traceId\":\""), forbidden.body());
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + port + path))
                .GET();
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
}
