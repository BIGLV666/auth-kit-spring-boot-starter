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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 真实的 Boot 4.2 消费方冒烟：登录 → Bearer 访问受保护接口 → 无 token 401 →
 * 匿名单点放行 → 踢人后旧 token 401。
 * <p>用 JDK HttpClient 而不是 Boot 测试客户端，避免 Boot 4 测试 API 包位移影响验证结论。</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = CompatApp.class)
class Boot4CompatTest {

    @Value("${local.server.port}")
    private int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void loginAnnotationAndKickWorkOnBoot4() throws Exception {
        String token = AuthKit.login("compat-user", "PC");

        HttpResponse<String> authenticated = get("/api/me", token);
        assertEquals(200, authenticated.statusCode());
        assertTrue(authenticated.body().contains("compat-user"));

        assertEquals(401, get("/api/me", null).statusCode());
        assertEquals(200, get("/api/open", null).statusCode());

        AuthKit.kickout("compat-user", "PC");
        assertEquals(401, get("/api/me", token).statusCode());
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
