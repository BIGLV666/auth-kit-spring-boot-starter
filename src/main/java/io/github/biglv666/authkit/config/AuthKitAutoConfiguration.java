package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.context.CurrentUserArgumentResolver;
import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.core.TokenResolver;
import io.github.biglv666.authkit.crypto.BCryptPasswordEncoderAdapter;
import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemorySafeStore;
import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.RedisAttemptStore;
import io.github.biglv666.authkit.dao.RedisSafeStore;
import io.github.biglv666.authkit.dao.RedisSessionDao;
import io.github.biglv666.authkit.dao.SafeStore;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import io.github.biglv666.authkit.interceptor.AuthInterceptor;
import io.github.biglv666.authkit.management.ManagementTokenFilter;
import io.github.biglv666.authkit.management.OnlineSessionController;
import io.github.biglv666.authkit.oauth2.OAuth2Properties;
import io.github.biglv666.authkit.oauth2.client.GitHubIdentityProvider;
import io.github.biglv666.authkit.oauth2.client.IdentityProvider;
import io.github.biglv666.authkit.oauth2.client.OAuth2ClientController;
import io.github.biglv666.authkit.oauth2.client.OAuth2UserBinder;
import io.github.biglv666.authkit.oauth2.client.WeComIdentityProvider;
import io.github.biglv666.authkit.oauth2.server.OAuth2AuthorizationServerController;
import io.github.biglv666.authkit.oauth2.store.InMemoryOAuth2KeyValueStore;
import io.github.biglv666.authkit.oauth2.store.OAuth2KeyValueStore;
import io.github.biglv666.authkit.oauth2.store.RedisOAuth2KeyValueStore;
import io.github.biglv666.authkit.spi.PasswordEncoder;
import io.github.biglv666.authkit.spi.PermissionProvider;
import io.github.biglv666.authkit.token.JwtTokenCodec;
import io.github.biglv666.authkit.token.OpaqueTokenCodec;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import io.github.biglv666.authkit.token.TokenCodec;
import io.github.biglv666.authkit.token.TokenGenerator;
import io.github.biglv666.authkit.webcommon.AuthKitDefaultExceptionHandler;
import io.github.biglv666.authkit.webcommon.AuthKitWebCommonExceptionHandler;
import io.github.biglv666.webcommon.result.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * auth-kit 自动装配入口。
 * <p>装配原则：所有 Bean {@code @ConditionalOnMissingBean}，业务方可全量替换任意一层
 * （SessionDao / AttemptStore / TokenGenerator / PermissionProvider / PasswordEncoder）。</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "auth-kit", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties({AuthKitProperties.class, OAuth2Properties.class})
public class AuthKitAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AuthKitAutoConfiguration.class);

    private static final String WEB_COMMON_RESULT = "io.github.biglv666.webcommon.result.Result";
    private static final String SPRING_SECURITY_BCRYPT =
            "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder";

    // ── 存储层 ──

    /**
     * 会话存储：store=memory 强制内存；auto 时类路径与容器中存在 RedisConnectionFactory 则用 Redis，
     * 否则降级内存（启动日志提示）；store=redis 但无 Redis 时 fail-fast。
     */
    @Bean
    @ConditionalOnMissingBean(SessionDao.class)
    public SessionDao sessionDao(AuthKitProperties properties,
                                 ObjectProvider<RedisConnectionFactory> factoryProvider) {
        String store = properties.getStore();
        if ("memory".equals(store)) {
            return new InMemorySessionDao();
        }
        RedisConnectionFactory factory = factoryProvider.getIfAvailable();
        if (factory != null) {
            log.info("[auth-kit] 会话存储：Redis（key 前缀 {}）", properties.getKeyPrefix());
            return new RedisSessionDao(new StringRedisTemplate(factory), properties.getKeyPrefix());
        }
        if ("redis".equals(store)) {
            throw new IllegalStateException(
                    "auth-kit.session.store=redis 但容器中不存在 RedisConnectionFactory，请检查 Redis 配置");
        }
        log.warn("[auth-kit] 未检测到 Redis，会话降级为内存存储（仅适合本地开发/单实例部署，重启即失联）");
        return new InMemorySessionDao();
    }

    /** 登录失败计数存储：选择逻辑同会话存储 */
    @Bean
    @ConditionalOnMissingBean(AttemptStore.class)
    public AttemptStore attemptStore(AuthKitProperties properties,
                                     ObjectProvider<RedisConnectionFactory> factoryProvider) {
        String store = properties.getStore();
        if ("memory".equals(store)) {
            return new InMemoryAttemptStore();
        }
        RedisConnectionFactory factory = factoryProvider.getIfAvailable();
        if (factory != null) {
            return new RedisAttemptStore(new StringRedisTemplate(factory));
        }
        if ("redis".equals(store)) {
            throw new IllegalStateException("auth-kit.session.store=redis 但容器中不存在 RedisConnectionFactory");
        }
        return new InMemoryAttemptStore();
    }

    /** 二级认证状态存储：选择逻辑同会话存储 */
    @Bean
    @ConditionalOnMissingBean(SafeStore.class)
    public SafeStore safeStore(AuthKitProperties properties,
                               ObjectProvider<RedisConnectionFactory> factoryProvider) {
        String store = properties.getStore();
        if ("memory".equals(store)) {
            return new InMemorySafeStore();
        }
        RedisConnectionFactory factory = factoryProvider.getIfAvailable();
        if (factory != null) {
            return new RedisSafeStore(new StringRedisTemplate(factory), properties.getKeyPrefix());
        }
        if ("redis".equals(store)) {
            throw new IllegalStateException("auth-kit.session.store=redis 但容器中不存在 RedisConnectionFactory");
        }
        return new InMemorySafeStore();
    }

    // ── 核心层 ──

    @Bean
    @ConditionalOnMissingBean(TokenGenerator.class)
    public TokenGenerator tokenGenerator(AuthKitProperties properties) {
        // style 标识保留扩展位，V1 仅支持 random-64；自定义策略请注册 TokenGenerator Bean
        if (!"random-64".equals(properties.getToken().getStyle())) {
            log.warn("[auth-kit] 未知的 token.style={}，回退 random-64", properties.getToken().getStyle());
        }
        return new RandomTokenGenerator(64);
    }

    @Bean
    @ConditionalOnMissingBean(TokenCodec.class)
    public TokenCodec tokenCodec(AuthKitProperties properties) {
        if ("jwt".equals(properties.getToken().getMode())) {
            String secret = properties.getToken().getJwtSecret();
            if (secret == null || secret.length() < 16) {
                throw new IllegalStateException(
                        "auth-kit.token.mode=jwt 时必须配置 auth-kit.token.jwt-secret（HS256 签名密钥，至少 16 字符）");
            }
            return new JwtTokenCodec(secret, properties.getTimeout().toMillis());
        }
        return new OpaqueTokenCodec();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthManager authManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                                   TokenCodec tokenCodec, SafeStore safeStore, AuthKitProperties properties,
                                   ObjectProvider<PermissionProvider> permissionProvider) {
        AuthManager manager = new AuthManager(
                sessionDao,
                tokenGenerator,
                properties.getTimeout().toMillis(),
                properties.getActiveTimeout().toMillis(),
                properties.getMaxSessionsPerDevice(),
                properties.getRememberTimeout().toMillis(),
                properties.getSafe().getDuration().toMillis());
        manager.setTokenCodec(tokenCodec);
        manager.setDeviceMaxSessions(properties.getSession().getDeviceMaxSessions());
        manager.setSafeStore(safeStore);
        PermissionProvider provider = permissionProvider.getIfAvailable();
        if (provider != null) {
            manager.setPermissionProvider(provider);
        }
        return manager;
    }

    /** 启动时初始化 AuthKit 静态门面 */
    @Bean
    public InitializingBean authKitInitializer(AuthManager authManager) {
        return () -> AuthKit.init(authManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenResolver tokenResolver(AuthKitProperties properties) {
        return new TokenResolver(properties.getHeaderName(), properties.getCookieName(), properties.getPrefix());
    }

    // ── 扩展层 ──

    /** 密码编码默认实现：类路径有 spring-security-crypto 时提供 BCrypt，否则业务方自配 Bean */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    @ConditionalOnClass(name = SPRING_SECURITY_BCRYPT)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoderAdapter();
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginAttemptGuard loginAttemptGuard(AttemptStore attemptStore, AuthKitProperties properties) {
        return new LoginAttemptGuard(attemptStore,
                properties.getFailMaxAttempts(), properties.getLockDuration().toMillis());
    }

    // ── 异常映射：有 web-common 用 Result，否则原生 401/403 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = WEB_COMMON_RESULT)
    static class WebCommonErrorConfig {

        @Bean
        @ConditionalOnMissingBean(AuthKitWebCommonExceptionHandler.class)
        public AuthKitWebCommonExceptionHandler authKitWebCommonExceptionHandler(AuthKitProperties properties) {
            return new AuthKitWebCommonExceptionHandler(properties.getKickedOutMessage());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnMissingClass(WEB_COMMON_RESULT)
    static class DefaultErrorConfig {

        @Bean
        @ConditionalOnMissingBean(name = "authKitWebCommonExceptionHandler")
        public AuthKitDefaultExceptionHandler authKitDefaultExceptionHandler() {
            return new AuthKitDefaultExceptionHandler();
        }
    }

    // ── OAuth2 / SSO：默认全关，启用任一侧才装配 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "auth-kit.oauth2", name = "server.enabled", havingValue = "true")
    static class OAuth2ServerConfig {

        @Bean
        @ConditionalOnMissingBean(OAuth2KeyValueStore.class)
        public OAuth2KeyValueStore oauth2KeyValueStore(AuthKitProperties properties,
                                                       ObjectProvider<RedisConnectionFactory> factoryProvider) {
            return AuthKitAutoConfiguration.createOAuth2Store(properties, factoryProvider);
        }

        @Bean
        public OAuth2AuthorizationServerController oauth2AuthorizationServerController(
                OAuth2Properties oauth2Properties, OAuth2KeyValueStore oauth2KeyValueStore,
                AuthManager authManager, TokenResolver tokenResolver) {
            validateServerClients(oauth2Properties);
            return new OAuth2AuthorizationServerController(oauth2Properties, oauth2KeyValueStore,
                    authManager, tokenResolver);
        }

        /**
         * fail-fast：启用授权服务器却未正确注册客户端，问题必须暴露在启动期，
         * 而不是等到第一次授权请求静默返回 invalid_client（对齐 6.8 管理端 fail-fast 惯例）。
         */
        private static void validateServerClients(OAuth2Properties oauth2Properties) {
            java.util.Map<String, OAuth2Properties.ClientRegistration> clients = oauth2Properties.getServer().getClients();
            if (clients == null || clients.isEmpty()) {
                throw new IllegalStateException(
                        "启用 auth-kit.oauth2.server 必须注册至少一个客户端（auth-kit.oauth2.server.clients.*）");
            }
            for (java.util.Map.Entry<String, OAuth2Properties.ClientRegistration> entry : clients.entrySet()) {
                OAuth2Properties.ClientRegistration client = entry.getValue();
                if (client.getClientSecret() == null || client.getClientSecret().isBlank()) {
                    throw new IllegalStateException(
                            "OAuth2 客户端 " + entry.getKey() + " 缺少 client-secret（本服务器仅支持机密客户端）");
                }
                if (client.getRedirectUris() == null || client.getRedirectUris().isEmpty()) {
                    throw new IllegalStateException(
                            "OAuth2 客户端 " + entry.getKey() + " 至少配置一个 redirect-uris（精确匹配，防开放重定向）");
                }
            }
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "auth-kit.oauth2.client", name = "enabled", havingValue = "true")
    static class OAuth2ClientConfig {

        @Bean
        @ConditionalOnMissingBean(OAuth2KeyValueStore.class)
        public OAuth2KeyValueStore oauth2KeyValueStoreForClient(AuthKitProperties properties,
                                                                ObjectProvider<RedisConnectionFactory> factoryProvider) {
            return AuthKitAutoConfiguration.createOAuth2Store(properties, factoryProvider);
        }

        @Bean
        public OAuth2ClientController oauth2ClientController(OAuth2Properties oauth2Properties,
                                                             OAuth2KeyValueStore oauth2KeyValueStore,
                                                             AuthManager authManager,
                                                             ObjectProvider<OAuth2UserBinder> binderProvider,
                                                             ObjectProvider<IdentityProvider> identityProviders) {
            // 内置 provider 与业务自定义 Bean（按 name() 去重，自定义优先）
            java.util.Map<String, IdentityProvider> providers = new java.util.LinkedHashMap<>();
            providers.put("github", new GitHubIdentityProvider());
            providers.put("wecom", new WeComIdentityProvider());
            for (IdentityProvider custom : identityProviders) {
                providers.put(custom.name(), custom);
            }
            OAuth2UserBinder binder = binderProvider.getIfAvailable();
            if (binder == null) {
                throw new IllegalStateException(
                        "启用 auth-kit.oauth2.client 必须注册 OAuth2UserBinder Bean（第三方档案 → 本地 userId 的绑定逻辑）");
            }
            return new OAuth2ClientController(oauth2Properties, oauth2KeyValueStore, authManager, binder, providers);
        }
    }

    /** OAuth2 KV 存储选择逻辑：有 Redis 用 Redis，否则内存 */
    private static OAuth2KeyValueStore createOAuth2Store(AuthKitProperties properties,
                                                         ObjectProvider<RedisConnectionFactory> factoryProvider) {
        RedisConnectionFactory factory = factoryProvider.getIfAvailable();
        if (factory != null) {
            return new RedisOAuth2KeyValueStore(new StringRedisTemplate(factory), properties.getKeyPrefix());
        }
        return new InMemoryOAuth2KeyValueStore();
    }

    /** 会话事件 → Spring 事件广播（SSO 各应用监听做本地清理） */
    @Bean
    public InitializingBean authKitEventBridge(AuthManager authManager,
                                               ObjectProvider<ApplicationEventPublisher> publisherProvider) {
        return () -> {
            ApplicationEventPublisher publisher = publisherProvider.getIfAvailable();
            if (publisher != null) {
                authManager.setEventListener(publisher::publishEvent);
            }
        };
    }

    // ── Web 层 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class AuthKitWebConfig {

        @Bean
        @ConditionalOnMissingBean
        public AuthInterceptor authInterceptor(AuthKitProperties properties, OAuth2Properties oauth2Properties,
                                               AuthManager authManager, TokenResolver tokenResolver) {
            return new AuthInterceptor(properties, oauth2Properties, authManager, tokenResolver);
        }

        @Bean
        public WebMvcConfigurer authKitWebMvcConfigurer(AuthInterceptor authInterceptor) {
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(authInterceptor).addPathPatterns("/**");
                }

                @Override
                public void addArgumentResolvers(java.util.List<org.springframework.web.method.support.HandlerMethodArgumentResolver> resolvers) {
                    resolvers.add(new CurrentUserArgumentResolver());
                }
            };
        }
    }

    // ── 管理端点：默认关闭，启用时必须配置静态令牌 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnProperty(prefix = "auth-kit.management", name = "enabled", havingValue = "true")
    static class ManagementConfig {

        @Bean
        public OnlineSessionController onlineSessionController(AuthManager authManager) {
            return new OnlineSessionController(authManager);
        }

        @Bean
        public FilterRegistrationBean<ManagementTokenFilter> managementTokenFilter(AuthKitProperties properties) {
            String authToken = properties.getAuthToken();
            if (authToken == null || authToken.isBlank()) {
                throw new IllegalStateException(
                        "auth-kit.management.enabled=true 时必须配置 auth-kit.management.auth-token（管理端点静态令牌）");
            }
            ManagementTokenFilter filter = new ManagementTokenFilter(
                    properties.getBasePath(), properties.getAuthHeader(), authToken);
            FilterRegistrationBean<ManagementTokenFilter> registration = new FilterRegistrationBean<>(filter);
            registration.addUrlPatterns("/*");
            registration.setOrder(1);
            return registration;
        }
    }
}
