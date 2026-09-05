package io.github.biglv666.authkit.oauth2.client;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import io.github.biglv666.authkit.oauth2.store.OAuth2KeyValueStore;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;

/**
 * 第三方登录端点：/oauth2/login/{provider} 跳平台授权页 →
 * /oauth2/callback/{provider} 换档案 → 业务绑定 → 签发 auth-kit 会话凭证。
 * <p>登录成功后 302 到配置的 success-redirect，token 以查询参数附带
 * （演示友好；生产建议改成前端引导页 + localStorage 或 POST 表单提交）。</p>
 */
@RestController
@RequestMapping("/oauth2")
public class OAuth2ClientController {

    private final OAuth2Properties properties;
    private final OAuth2KeyValueStore store;
    private final AuthManager authManager;
    private final OAuth2UserBinder binder;
    private final Map<String, IdentityProvider> providers;
    private final RandomTokenGenerator random = new RandomTokenGenerator(32);

    public OAuth2ClientController(OAuth2Properties properties, OAuth2KeyValueStore store,
                                  AuthManager authManager, OAuth2UserBinder binder,
                                  Map<String, IdentityProvider> providers) {
        this.properties = properties;
        this.store = store;
        this.authManager = authManager;
        this.binder = binder;
        this.providers = providers;
    }

    /**
     * 发起第三方登录：302 到平台授权页（state 防 CSRF，10 分钟有效）。
     */
    @GetMapping("/login/{provider}")
    public RedirectView login(@PathVariable("provider") String provider) {
        IdentityProvider identityProvider = providers.get(provider);
        OAuth2Properties.ProviderConfig config = configured(provider);
        if (identityProvider == null || config == null) {
            throw new IllegalArgumentException("未配置的登录方式: " + provider);
        }
        String state = random.generate();
        // state 记录 provider 名，回调时校验归属与时效
        store.put("state:" + state, provider, 10 * 60 * 1000L);
        return new RedirectView(identityProvider.authorizeUrl(config, config.getRedirectUri(), state));
    }

    /**
     * 平台回调：校验 state → 换档案 → 业务绑定 → 签发凭证 → 落地页。
     */
    @GetMapping("/callback/{provider}")
    public Object callback(@PathVariable("provider") String provider,
                           @RequestParam(value = "code", required = false) String code,
                           @RequestParam(value = "state", required = false) String state) {
        // state 单次消费且必须归属当前 provider，防止 CSRF 与跨平台混用
        String stateProvider = state == null ? null : store.remove("state:" + state);
        if (stateProvider == null || !stateProvider.equals(provider)) {
            return Map.of("error", "invalid_state", "error_description", "state 无效或已过期");
        }
        IdentityProvider identityProvider = providers.get(provider);
        OAuth2Properties.ProviderConfig config = configured(provider);
        if (identityProvider == null || config == null || code == null || code.isBlank()) {
            return Map.of("error", "invalid_request", "error_description", "回调参数不完整");
        }
        OAuth2UserProfile profile = identityProvider.exchange(config, code, config.getRedirectUri());
        String userId = binder.bind(profile);
        if (userId == null) {
            return Map.of("error", "access_denied", "error_description", "该第三方账号未绑定本地用户");
        }
        String token = authManager.login(userId, "OAuth2:" + provider);
        String redirect = properties.getClient().getSuccessRedirect();
        return new RedirectView(redirect + (redirect.contains("?") ? "&" : "?")
                + "token=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    private OAuth2Properties.ProviderConfig configured(String provider) {
        return properties.getClient().getProviders().get(provider);
    }
}
