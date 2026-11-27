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
 * hisdata 同栈冒烟：Spring Boot 4.2 + web-common 0.5.0 + auth-kit 1.3.0。
 *
 * <p>web-common 约定 HTTP 恒 200、业务成败看 body.code；auth-kit 的
 * {@code AuthKitWebCommonExceptionHandler} 必须优先于 web-common 的兜底异常处理器，
 * 返回 40100/40300，而不是被包装成 50000 或二次包装。</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = CompatApp.class)
class Boot4CompatTest {

    @Value("${local.server.port}")
    private int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void loginAnnotationAndKickWorkWithWebCommon05() throws Exception {
        String token = AuthKit.login("compat-user", "PC");

        HttpResponse<String> authenticated = get("/api/me", token);
        assertEquals(200, authenticated.statusCode());
        assertTrue(authenticated.body().contains("compat-user"));
        assertTrue(authenticated.body().contains("\"code\":0"),
                "web-common 自动包装应生效: " + authenticated.body());

        HttpResponse<String> forbidden = get("/api/admin", token);
        assertEquals(200, forbidden.statusCode());
        assertTrue(forbidden.body().contains("\"code\":40300"),
                "无权限必须映射为 40300: " + forbidden.body());

        HttpResponse<String> anonymous = get("/api/me", null);
        assertEquals(200, anonymous.statusCode(), "web-common 约定 HTTP 恒 200");
        assertTrue(anonymous.body().contains("\"code\":40100"),
                "auth-kit 异常必须映射为 40100，而不是 web-common 兜底 50000: " + anonymous.body());

        HttpResponse<String> open = get("/api/open", null);
        assertEquals(200, open.statusCode());

        AuthKit.kickout("compat-user", "PC");
        HttpResponse<String> kicked = get("/api/me", token);
        assertEquals(200, kicked.statusCode());
        assertTrue(kicked.body().contains("\"code\":40100"),
                "被踢下线必须映射为 40100: " + kicked.body());
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
