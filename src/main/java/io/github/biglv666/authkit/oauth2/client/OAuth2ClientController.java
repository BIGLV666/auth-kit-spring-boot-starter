package io.github.biglv666.authkit.oauth2.client;

import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import io.github.biglv666.authkit.oauth2.store.OAuth2KeyValueStore;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 第三方登录端点：/oauth2/login/{provider} 跳平台授权页 →
 * /oauth2/callback/{provider} 换档案 → 业务绑定 → 签发 auth-kit 会话凭证。
 * <p>登录成功后 302 到配置的 success-redirect，token 以查询参数附带
 * （演示友好；生产建议改成前端引导页 + localStorage 或 POST 表单提交）。</p>
 * <p>已知边界：state 不绑定发起浏览器会话，理论上存在 login CSRF
 * （攻击者诱导受害者用攻击者凭证完成回调）；轻量实现的取舍，见 USAGE 9.2。</p>
 */
@RestController
@RequestMapping("/oauth2")
public class OAuth2ClientController {

    private static final Logger log = LoggerFactory.getLogger(OAuth2ClientController.class);

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
     * 未配置的登录方式返回 404（而不是 500），便于前端区分"入口写错"与"服务故障"。
     */
    @GetMapping("/login/{provider}")
    public Object login(@PathVariable("provider") String provider) {
        IdentityProvider identityProvider = providers.get(provider);
        OAuth2Properties.ProviderConfig config = configured(provider);
        if (identityProvider == null || config == null) {
            return loginError(404, "unknown_provider", "未配置的登录方式: " + provider);
        }
        String state = random.generate();
        // state 记录 provider 名，回调时校验归属与时效
        store.put("state:" + state, provider, 10 * 60 * 1000L);
        return new RedirectView(identityProvider.authorizeUrl(config, config.getRedirectUri(), state));
    }

    /**
     * 平台回调：校验 state → 换档案 → 业务绑定 → 签发凭证 → 落地页。
     * <p>平台拒绝授权时回传 {@code error} 参数，直接以 400 结束，不再尝试换档案；
     * 换档案失败仅记服务端日志（避免平台响应细节泄漏给浏览器），对外统一 400。</p>
     */
    @GetMapping("/callback/{provider}")
    public Object callback(@PathVariable("provider") String provider,
                           @RequestParam(value = "code", required = false) String code,
                           @RequestParam(value = "state", required = false) String state,
                           @RequestParam(value = "error", required = false) String platformError,
                           @RequestParam(value = "error_description", required = false) String platformErrorDesc) {
        // 平台侧拒绝授权（用户取消等）：不再发起换档案请求
        if (platformError != null && !platformError.isBlank()) {
            return loginError(400, platformError,
                    platformErrorDesc == null ? "第三方平台拒绝授权" : platformErrorDesc);
        }
        // state 单次消费且必须归属当前 provider，防止 CSRF 与跨平台混用
        String stateProvider = state == null ? null : store.remove("state:" + state);
        if (stateProvider == null || !stateProvider.equals(provider)) {
            return loginError(400, "invalid_state", "state 无效或已过期");
        }
        IdentityProvider identityProvider = providers.get(provider);
        OAuth2Properties.ProviderConfig config = configured(provider);
        if (identityProvider == null || config == null || code == null || code.isBlank()) {
            return loginError(400, "invalid_request", "回调参数不完整");
        }
        OAuth2UserProfile profile;
        try {
            profile = identityProvider.exchange(config, code, config.getRedirectUri());
        } catch (Exception e) {
            // 平台响应可能含 access_token 等敏感信息，只入服务端日志，不回显浏览器
            log.warn("OAuth2 回调换档案失败（provider={}）: {}", provider, e.getMessage());
            return loginError(400, "invalid_grant", "第三方档案换取失败");
        }
        String userId = binder.bind(profile);
        if (userId == null) {
            return loginError(400, "access_denied", "该第三方账号未绑定本地用户");
        }
        // device 带随机后缀：同一用户多点经第三方登录互不顶号（与 server 侧签发语义一致）
        String token = authManager.login(userId, "OAuth2:" + provider + "#" + random.generate().substring(0, 8));
        String redirect = properties.getClient().getSuccessRedirect();
        return new RedirectView(redirect + (redirect.contains("?") ? "&" : "?")
                + "token=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    /** 浏览器可见的错误响应：status 明确（400/404），body 为 OAuth2 风格 error 结构 */
    private static ResponseEntity<Map<String, Object>> loginError(int status, String error, String description) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("error", error);
        resp.put("error_description", description);
        return ResponseEntity.status(status).body(resp);
    }

    private OAuth2Properties.ProviderConfig configured(String provider) {
        return properties.getClient().getProviders().get(provider);
    }
}
