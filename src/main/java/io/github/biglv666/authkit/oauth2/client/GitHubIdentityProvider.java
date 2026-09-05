package io.github.biglv666.authkit.oauth2.client;

import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import org.springframework.web.client.RestClient;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * GitHub 登录实现：标准 OAuth2 authorization_code 流。
 * <ul>
 *   <li>授权页：https://github.com/login/oauth/authorize</li>
 *   <li>换 token：POST https://github.com/login/oauth/access_token（Accept: application/json）</li>
 *   <li>用户档案：GET https://api.github.com/user</li>
 * </ul>
 */
public class GitHubIdentityProvider implements IdentityProvider {

    private final RestClient restClient;

    public GitHubIdentityProvider() {
        this(RestClient.create());
    }

    /** 注入 RestClient 便于测试桩替换 */
    public GitHubIdentityProvider(RestClient restClient) {
        this.restClient = restClient;
    }

    @Override
    public String name() {
        return "github";
    }

    @Override
    public String authorizeUrl(OAuth2Properties.ProviderConfig config, String redirectUri, String state) {
        return "https://github.com/login/oauth/authorize"
                + "?client_id=" + urlEncode(config.getClientId())
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&scope=read:user"
                + "&state=" + urlEncode(state);
    }

    @Override
    @SuppressWarnings("unchecked")
    public OAuth2UserProfile exchange(OAuth2Properties.ProviderConfig config, String code, String redirectUri) {
        Map<String, Object> token = restClient.post()
                .uri("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .body(Map.of("client_id", config.getClientId(),
                        "client_secret", config.getClientSecret(),
                        "code", code,
                        "redirect_uri", redirectUri))
                .retrieve()
                .body(Map.class);
        String accessToken = token == null ? null : (String) token.get("access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalStateException("GitHub 换取 access_token 失败: " + token);
        }
        Map<String, Object> user = restClient.get()
                .uri("https://api.github.com/user")
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/vnd.github+json")
                .retrieve()
                .body(Map.class);
        if (user == null || user.get("id") == null) {
            throw new IllegalStateException("GitHub 拉取用户信息失败");
        }
        return new OAuth2UserProfile("github",
                String.valueOf(user.get("id")),
                (String) user.get("login"),
                (String) user.get("name"),
                (String) user.get("email"),
                new LinkedHashMap<>(user));
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }
}
