package io.github.biglv666.authkit.oauth2.server;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import io.github.biglv666.authkit.oauth2.store.OAuth2KeyValueStore;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 轻量授权服务器（authorization_code + refresh_token，仅此两种 grant）。
 * <p>核心设计：签发的 access_token 就是 auth-kit 会话凭证——资源端校验复用现有
 * checkLogin 拦截链，SSO 由多应用共享 Redis 会话天然实现。</p>
 * <p>未登录访问 authorize 时跳转到配置的业务登录页（login-page），
 * 业务登录成功后需携带用户回到原 authorize 地址。</p>
 */
@RestController
@RequestMapping("/oauth2")
public class OAuth2AuthorizationServerController {

    private final OAuth2Properties properties;
    private final OAuth2KeyValueStore store;
    private final AuthManager authManager;
    private final io.github.biglv666.authkit.core.TokenResolver tokenResolver;
    private final RandomTokenGenerator random = new RandomTokenGenerator(32);

    public OAuth2AuthorizationServerController(OAuth2Properties properties,
                                               OAuth2KeyValueStore store,
                                               AuthManager authManager,
                                               io.github.biglv666.authkit.core.TokenResolver tokenResolver) {
        this.properties = properties;
        this.store = store;
        this.authManager = authManager;
        this.tokenResolver = tokenResolver;
    }

    /**
     * 授权端点：校验客户端与回调地址 → 未登录跳业务登录页 → 已登录签发授权码并回跳。
     */
    @GetMapping("/authorize")
    public Object authorize(@RequestParam("response_type") String responseType,
                            @RequestParam("client_id") String clientId,
                            @RequestParam("redirect_uri") String redirectUri,
                            @RequestParam(value = "scope", required = false) String scope,
                            @RequestParam(value = "state", required = false) String state,
                            HttpServletRequest request) {
        OAuth2Properties.ClientRegistration client = registeredClient(clientId);
        if (client == null || !client.getRedirectUris().contains(redirectUri)) {
            return oauthError("invalid_client", "未注册的 client_id 或 redirect_uri 不匹配");
        }
        if (!"code".equals(responseType)) {
            return oauthError("unsupported_response_type", "仅支持 response_type=code");
        }
        if (scope != null && !scope.isBlank() && !client.getScopes().isEmpty()) {
            for (String s : scope.split(" ")) {
                if (!client.getScopes().contains(s)) {
                    return oauthError("invalid_scope", "scope 超出注册范围: " + s);
                }
            }
        }
        // /oauth2/authorize|token 在拦截器白名单内（精确端点匹配），登录态需从请求头自行解析
        String userId = resolveUserId(request);
        if (userId == null) {
            String back = request.getRequestURL() + buildAuthorizeQuery(responseType, clientId, redirectUri, scope, state);
            return new RedirectView(properties.getServer().getLoginPage()
                    + (properties.getServer().getLoginPage().contains("?") ? "&" : "?")
                    + "redirect=" + urlEncode(back));
        }
        String code = random.generate();
        store.put("code:" + code, encodeGrant(userId, clientId, redirectUri), properties.getServer().getCodeTtl().toMillis());
        return new RedirectView(redirectUri + (redirectUri.contains("?") ? "&" : "?")
                + "code=" + urlEncode(code) + (state == null ? "" : "&state=" + urlEncode(state)));
        // buildAuthorizeQuery 仅供跳转登录页时还原原始请求
    }

    private String buildAuthorizeQuery(String responseType, String clientId, String redirectUri,
                                       String scope, String state) {
        StringBuilder sb = new StringBuilder("?");
        sb.append("response_type=code").append("&client_id=").append(urlEncode(clientId))
                .append("&redirect_uri=").append(urlEncode(redirectUri));
        if (scope != null) {
            sb.append("&scope=").append(urlEncode(scope));
        }
        if (state != null) {
            sb.append("&state=").append(urlEncode(state));
        }
        return sb.toString();
    }

    /**
     * 令牌端点：authorization_code / refresh_token 两种 grant。
     * <p>access_token 即 auth-kit 会话凭证；refresh_token 轮换（旧的立即作废）。</p>
     */
    @PostMapping("/token")
    public Object token(@RequestParam("grant_type") String grantType,
                        @RequestParam(value = "client_id", required = false) String clientId,
                        @RequestParam(value = "client_secret", required = false) String clientSecret,
                        @RequestParam(value = "code", required = false) String code,
                        @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                        @RequestParam(value = "refresh_token", required = false) String refreshToken) {
        if ("authorization_code".equals(grantType)) {
            return authorizationCodeGrant(clientId, clientSecret, code, redirectUri);
        }
        if ("refresh_token".equals(grantType)) {
            return refreshTokenGrant(clientId, clientSecret, refreshToken);
        }
        return oauthError("unsupported_grant_type", "仅支持 authorization_code / refresh_token");
    }

    private Object authorizationCodeGrant(String clientId, String clientSecret,
                                          String code, String redirectUri) {
        OAuth2Properties.ClientRegistration client = registeredClient(clientId);
        if (client == null || !constantEquals(client.getClientSecret(), clientSecret)) {
            return oauthError("invalid_client", "client_id 或 client_secret 错误");
        }
        if (code == null || code.isBlank()) {
            return oauthError("invalid_grant", "缺少授权码");
        }
        // GETDEL 语义：授权码一次性消费，防重放
        String data = store.remove("code:" + code);
        if (data == null) {
            return oauthError("invalid_grant", "授权码无效或已使用");
        }
        String[] parts = decodeGrant(data);
        // RFC 6749 4.1.3：authorize 带 redirect_uri 时 token 请求必须原样带回；
        // 客户端漏带（null）按不匹配处理，不得 NPE（之前直接 500）
        if (!clientId.equals(parts[1]) || !java.util.Objects.equals(redirectUri, parts[2])) {
            return oauthError("invalid_grant", "授权码与 client_id/redirect_uri 不匹配");
        }
        return issueTokens(parts[0], clientId);
    }

    private Object refreshTokenGrant(String clientId, String clientSecret, String refreshToken) {
        OAuth2Properties.ClientRegistration client = registeredClient(clientId);
        if (client == null || !constantEquals(client.getClientSecret(), clientSecret)) {
            return oauthError("invalid_client", "client_id 或 client_secret 错误");
        }
        if (refreshToken == null || refreshToken.isBlank()) {
            return oauthError("invalid_grant", "缺少 refresh_token");
        }
        // 轮换：旧 refresh_token 立即作废
        String data = store.remove("refresh:" + refreshToken);
        if (data == null) {
            return oauthError("invalid_grant", "refresh_token 无效或已轮换");
        }
        String[] parts = decodeGrant(data);
        if (!clientId.equals(parts[1])) {
            return oauthError("invalid_grant", "refresh_token 与 client_id 不匹配");
        }
        return issueTokens(parts[0], clientId);
    }

    /**
     * 签发令牌对：access_token = auth-kit 会话凭证（device=clientId#随机后缀，
     * 每个令牌独立会话互不顶号）；refresh_token 轮换存储。
     */
    private Map<String, Object> issueTokens(String userId, String clientId) {
        long ttl = properties.getServer().getRefreshTtl().toMillis();
        String accessToken = authManager.login(userId, "OAuth2:" + clientId + "#" + random.generate().substring(0, 8));
        String refreshToken = random.generate();
        store.put("refresh:" + refreshToken, encodeGrant(userId, clientId), ttl);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", accessToken);
        resp.put("refresh_token", refreshToken);
        resp.put("token_type", "Bearer");
        resp.put("expires_in", authManager.getTimeoutMillis() / 1000);
        return resp;
    }

    private OAuth2Properties.ClientRegistration registeredClient(String clientId) {
        if (clientId == null) {
            return null;
        }
        return properties.getServer().getClients().get(clientId);
    }

    /** 从请求头软解析登录态（/oauth2/ 路径被拦截器放行，上下文未填充） */
    private String resolveUserId(HttpServletRequest request) {
        String token = tokenResolver.resolve(request);
        if (token == null) {
            return null;
        }
        try {
            return authManager.checkLogin(token).getUserId();
        } catch (io.github.biglv666.authkit.exception.NotLoginException e) {
            return null;
        }
    }

    /**
     * OAuth2 标准错误结构：统一 HTTP 400（RFC 6749 5.2），
     * 不回显密钥等敏感细节。消费者无响应包装时得到标准 {@code {error, error_description}} 结构。
     */
    private static ResponseEntity<Map<String, Object>> oauthError(String error, String description) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("error", error);
        resp.put("error_description", description);
        return ResponseEntity.badRequest().body(resp);
    }

    private String encodeGrant(String userId, String clientId, String redirectUri) {
        return urlEncode(userId) + "\n" + urlEncode(clientId) + "\n" + urlEncode(redirectUri == null ? "" : redirectUri);
    }

    private String encodeGrant(String userId, String clientId) {
        return urlEncode(userId) + "\n" + urlEncode(clientId) + "\n";
    }

    private String[] decodeGrant(String data) {
        String[] parts = data.split("\n");
        for (int i = 0; i < parts.length; i++) {
            parts[i] = urlDecode(parts[i]);
        }
        return parts;
    }

    /** 常量时间密钥比较，防时序攻击 */
    private static boolean constantEquals(String expected, String provided) {
        if (expected == null || provided == null) {
            return false;
        }
        byte[] a = expected.getBytes(StandardCharsets.UTF_8);
        byte[] b = provided.getBytes(StandardCharsets.UTF_8);
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String urlDecode(String value) {
        return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
