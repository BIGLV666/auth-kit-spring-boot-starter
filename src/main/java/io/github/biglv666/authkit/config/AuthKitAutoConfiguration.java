package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.context.CurrentUserArgumentResolver;
import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.core.TokenResolver;
import io.github.biglv666.authkit.crypto.BCryptPasswordEncoderAdapter;
import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemoryRiskControlStore;
import io.github.biglv666.authkit.dao.InMemorySafeStore;
import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.RedisAttemptStore;
import io.github.biglv666.authkit.dao.RedisRiskControlStore;
import io.github.biglv666.authkit.dao.RedisSafeStore;
import io.github.biglv666.authkit.dao.RedisSessionDao;
import io.github.biglv666.authkit.dao.SafeStore;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.guard.GuardMode;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import io.github.biglv666.authkit.guard.RiskControlPolicy;
import io.github.biglv666.authkit.guard.RiskControlStore;
import io.github.biglv666.authkit.interceptor.AuthInterceptor;
import io.github.biglv666.authkit.management.ConfigManagementTokenProvider;
import io.github.biglv666.authkit.management.ManagementTokenFilter;
import io.github.biglv666.authkit.management.ManagementTokenProvider;
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

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * auth-kit 自动装配入口。
 * <p>装配原则：所有 Bean {@code @ConditionalOnMissingBean}，业务方可全量替换任意一层
 * （SessionDao / AttemptStore / RiskControlStore / TokenGenerator / PermissionProvider / PasswordEncoder）。</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "auth-kit", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties({AuthKitProperties.class, OAuth2Properties.class})
public class AuthKitAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AuthKitAutoConfiguration.class);

    private static final String WEB_COMMON_RESULT = "io.github.biglv666.webcommon.result.Result";
    private static final String REDIS_FACTORY =
            "org.springframework.data.redis.connection.RedisConnectionFactory";
    private static final String SPRING_SECURITY_BCRYPT =
            "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder";

    // ── 存储层：按类路径是否存在 spring-data-redis 拆成两套装配 ──
    //
    // 不能只靠 optional 依赖：Bean 方法签名直接引用 RedisConnectionFactory 时，
    // 没有 spring-data-redis 的使用方会在启动期抛 ClassNotFoundException。
    // 因此 Redis 相关 Bean 必须放进 @ConditionalOnClass 的嵌套配置。

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = REDIS_FACTORY)
    static class RedisAwareStorageConfig {

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

        @Bean
        @ConditionalOnMissingBean(RiskControlStore.class)
        public RiskControlStore riskControlStore(AuthKitProperties properties,
                                                 ObjectProvider<RedisConnectionFactory> factoryProvider) {
            boolean riskStoreRequired = properties.getGuard().getMode() == GuardMode.RISK_CONTROL
                    && properties.isGuardEnabled() && properties.getFailMaxAttempts() > 0;
            String store = properties.getStore();
            if ("memory".equals(store)) {
                return new InMemoryRiskControlStore();
            }
            RedisConnectionFactory factory = factoryProvider.getIfAvailable();
            if (factory != null) {
                return new RedisRiskControlStore(new StringRedisTemplate(factory));
            }
            if (riskStoreRequired && "redis".equals(store)) {
                throw new IllegalStateException("auth-kit.session.store=redis 但容器中不存在 RedisConnectionFactory");
            }
            return new InMemoryRiskControlStore();
        }

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
    }

    /** 类路径没有 spring-data-redis：只能内存；store=redis 时启动失败（fail-fast） */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingClass(REDIS_FACTORY)
    static class NoRedisStorageConfig {

        @Bean
        @ConditionalOnMissingBean(SessionDao.class)
        public SessionDao sessionDao(AuthKitProperties properties) {
            failIfRedisRequired(properties);
            log.warn("[auth-kit] 类路径无 spring-data-redis，会话使用内存存储（仅适合本地开发/单实例）");
            return new InMemorySessionDao();
        }

        @Bean
        @ConditionalOnMissingBean(AttemptStore.class)
        public AttemptStore attemptStore(AuthKitProperties properties) {
            failIfRedisRequired(properties);
            return new InMemoryAttemptStore();
        }

        @Bean
        @ConditionalOnMissingBean(RiskControlStore.class)
        public RiskControlStore riskControlStore(AuthKitProperties properties) {
            // 与 RedisAwareStorageConfig 保持一致：只有 risk-control 真正启用且 store=redis 才失败，
            // 其他场景允许内存降级（不影响 counter 模式/自定义存储）。
            boolean riskStoreRequired = properties.getGuard().getMode() == GuardMode.RISK_CONTROL
                    && properties.isGuardEnabled() && properties.getFailMaxAttempts() > 0;
            if (riskStoreRequired && "redis".equals(properties.getStore())) {
                throw new IllegalStateException(
                        "auth-kit.guard.mode=risk-control 且 store=redis，但类路径缺少 spring-data-redis");
            }
            return new InMemoryRiskControlStore();
        }

        @Bean
        @ConditionalOnMissingBean(SafeStore.class)
        public SafeStore safeStore(AuthKitProperties properties) {
            failIfRedisRequired(properties);
            return new InMemorySafeStore();
        }

        private static void failIfRedisRequired(AuthKitProperties properties) {
            if ("redis".equals(properties.getStore())) {
                throw new IllegalStateException(
                        "auth-kit.session.store=redis 但类路径缺少 spring-data-redis，请引入依赖或改用 memory/auto");
            }
        }
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
        return new TokenResolver(properties.getHeaderName(), properties.getCookieName(),
                properties.getPrefix(), properties.getToken().getQueryParameterName());
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
    public LoginAttemptGuard loginAttemptGuard(AttemptStore attemptStore,
                                               RiskControlStore riskControlStore,
                                               AuthKitProperties properties) {
        if (properties.getGuard().getMode() == GuardMode.RISK_CONTROL) {
            RiskControlPolicy policy = riskControlPolicy(properties);
            boolean enabled = properties.isGuardEnabled() && policy.maxAttempts() > 0;
            return new LoginAttemptGuard(riskControlStore, policy, properties.getKeyPrefix(), enabled);
        }
        // counter 模式：guard.enabled=false 时把阈值置 0，守卫自身即完全停用
        int maxAttempts = properties.isGuardEnabled() ? properties.getFailMaxAttempts() : 0;
        return new LoginAttemptGuard(attemptStore,
                maxAttempts, properties.getLockDuration().toMillis(),
                properties.getKeyPrefix());
    }

    private RiskControlPolicy riskControlPolicy(AuthKitProperties properties) {
        AuthKitProperties.Guard guard = properties.getGuard();
        requireConfigured(guard.getAttemptWindow(), "attempt-window");
        requireConfigured(guard.getLockoutResetInterval(), "lockout-reset-interval");
        requireConfigured(guard.getStateTtl(), "state-ttl");

        List<Duration> configured = guard.getLockoutDurations();
        List<Long> durations = new ArrayList<>();
        if (configured != null) {
            for (Duration duration : configured) {
                if (duration == null) {
                    throw new IllegalArgumentException("auth-kit.guard.lockout-durations 不能包含空值");
                }
                durations.add(duration.toMillis());
            }
        }
        return new RiskControlPolicy(
                guard.getAttemptWindow().toMillis(),
                guard.getFailMaxAttempts(),
                durations,
                guard.getLockoutResetInterval().toMillis(),
                guard.getStateTtl().toMillis(),
                guard.isResetOnSuccess());
    }

    private static void requireConfigured(Duration value, String name) {
        if (value == null) {
            throw new IllegalArgumentException("auth-kit.guard." + name + " 不能为空");
        }
    }

    // ── 异常映射：有 web-common 用 Result，否则原生 401/403 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = WEB_COMMON_RESULT)
    static class WebCommonErrorConfig {

        @Bean
        @ConditionalOnMissingBean(AuthKitWebCommonExceptionHandler.class)
        public AuthKitWebCommonExceptionHandler authKitWebCommonExceptionHandler(
                AuthKitProperties properties,
                ObjectProvider<io.github.biglv666.webcommon.config.WebCommonProperties> webCommonProperties) {
            // web-common 的配置 Bean（存在则支持 SEMANTIC 状态码与 traceId 透传）
            return new AuthKitWebCommonExceptionHandler(properties.getKickedOutMessage(),
                    webCommonProperties.getIfAvailable());
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

    /**
     * OAuth2 KV 存储：类路径有 spring-data-redis 时优先 Redis，否则内存。
     * <p>与存储层同样按类存在性隔离，避免无 Redis 依赖的使用方启动失败。</p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = REDIS_FACTORY)
    static class RedisOAuth2StoreConfig {

        @Bean
        @ConditionalOnMissingBean(OAuth2KeyValueStore.class)
        public OAuth2KeyValueStore oauth2KeyValueStore(AuthKitProperties properties,
                                                       ObjectProvider<RedisConnectionFactory> factoryProvider) {
            RedisConnectionFactory factory = factoryProvider.getIfAvailable();
            if (factory != null) {
                return new RedisOAuth2KeyValueStore(new StringRedisTemplate(factory),
                        properties.getKeyPrefix());
            }
            return new InMemoryOAuth2KeyValueStore();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingClass(REDIS_FACTORY)
    static class MemoryOAuth2StoreConfig {

        @Bean
        @ConditionalOnMissingBean(OAuth2KeyValueStore.class)
        public OAuth2KeyValueStore oauth2KeyValueStore() {
            return new InMemoryOAuth2KeyValueStore();
        }
    }

    /**
     * 会话事件 / 认证审计事件 → Spring 事件广播。
     * <p>使用 addEventListener/addAuditListener，允许 SSO、指标、审计日志各自监听、互不覆盖。</p>
     */
    @Bean
    public InitializingBean authKitEventBridge(
            AuthManager authManager,
            ObjectProvider<LoginAttemptGuard> guardProvider,
            ObjectProvider<io.github.biglv666.authkit.observability.AuthKitMetrics> metricsProvider,
            ObjectProvider<io.github.biglv666.authkit.observability.AuthKitAuditLogger> auditLoggerProvider,
            ObjectProvider<ApplicationEventPublisher> publisherProvider) {
        return () -> {
            LoginAttemptGuard guard = guardProvider.getIfAvailable();
            io.github.biglv666.authkit.observability.AuthKitMetrics metrics =
                    metricsProvider.getIfAvailable();
            io.github.biglv666.authkit.observability.AuthKitAuditLogger auditLogger =
                    auditLoggerProvider.getIfAvailable();

            // 指标/审计日志直接注册为监听器：监听器之间互相隔离，
            // 不依赖 Spring 事件多播（默认 multicaster 遇到第一个异常会中断后续监听器）。
            if (metrics != null) {
                authManager.addAuditListener(metrics::onAudit);
                authManager.addEventListener(metrics::onSession);
                if (guard != null) {
                    guard.addAuditListener(metrics::onAudit);
                }
            }
            if (auditLogger != null) {
                authManager.addAuditListener(auditLogger::onAudit);
                authManager.addEventListener(auditLogger::onSession);
                if (guard != null) {
                    guard.addAuditListener(auditLogger::onAudit);
                }
            }

            // Spring 事件最后注册：业务 @EventListener 仍可订阅；即使它抛异常，
            // 上面的指标/审计监听器已经执行完毕。
            ApplicationEventPublisher publisher = publisherProvider.getIfAvailable();
            if (publisher != null) {
                authManager.addEventListener(publisher::publishEvent);
                authManager.addAuditListener(publisher::publishEvent);
                if (guard != null) {
                    guard.addAuditListener(publisher::publishEvent);
                }
            }
        };
    }

    // ── 可观测性：全部可选依赖，缺失时静默不装配 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    static class MetricsConfig {

        /**
         * 不使用 {@code @ConditionalOnBean}：自动配置按类名排序，本组件可能先于
         * Micrometer 的 MetricsAutoConfiguration 评估，导致指标永远不注册。
         * 改为运行时取 ObjectProvider，缺 MeterRegistry 时退化为 no-op。
         */
        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnProperty(prefix = "auth-kit.observability", name = "metrics",
                havingValue = "true", matchIfMissing = true)
        public io.github.biglv666.authkit.observability.AuthKitMetrics authKitMetrics(
                ObjectProvider<io.micrometer.core.instrument.MeterRegistry> registryProvider) {
            return new io.github.biglv666.authkit.observability.AuthKitMetrics(
                    registryProvider.getIfAvailable());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthIndicator")
    @ConditionalOnProperty(prefix = "auth-kit.observability", name = "health",
            havingValue = "true", matchIfMissing = true)
    static class HealthConfig {

        @Configuration(proxyBeanMethods = false)
        @ConditionalOnClass(name = REDIS_FACTORY)
        static class RedisHealth {

            @Bean
            @ConditionalOnMissingBean(name = "authKitHealthIndicator")
            public org.springframework.boot.actuate.health.HealthIndicator authKitHealthIndicator(
                    SessionDao sessionDao,
                    ObjectProvider<RedisConnectionFactory> factoryProvider,
                    AuthKitProperties properties) {
                RedisConnectionFactory factory = factoryProvider.getIfAvailable();
                java.util.function.Supplier<org.springframework.boot.actuate.health.Health> probe;
                if ("memory".equals(properties.getStore())) {
                    // 显式选择内存存储：健康检查跟随内存语义，不探测 Redis
                    probe = null;
                } else if (factory != null) {
                    probe = new io.github.biglv666.authkit.observability.RedisHealthProbe(factory);
                } else {
                    // spring-data-redis 在类路径但容器没有 Redis 连接工厂：
                    // auto 会静默降级内存，生产多实例下这是严重问题，健康检查必须报 DOWN。
                    probe = () -> org.springframework.boot.actuate.health.Health.down()
                            .withDetail("store", "redis")
                            .withDetail("error", "RedisConnectionFactory missing")
                            .build();
                }
                return new io.github.biglv666.authkit.observability.AuthKitHealthIndicator(
                        sessionDao,
                        properties.getObservability().isMemoryStoreHealthUp(),
                        probe);
            }
        }

        @Configuration(proxyBeanMethods = false)
        @ConditionalOnMissingClass(REDIS_FACTORY)
        static class MemoryHealth {

            @Bean
            @ConditionalOnMissingBean(name = "authKitHealthIndicator")
            public org.springframework.boot.actuate.health.HealthIndicator authKitHealthIndicator(
                    SessionDao sessionDao, AuthKitProperties properties) {
                return new io.github.biglv666.authkit.observability.AuthKitHealthIndicator(
                        sessionDao,
                        properties.getObservability().isMemoryStoreHealthUp(),
                        null);
            }
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "auth-kit.observability", name = "audit-log",
            havingValue = "true", matchIfMissing = true)
    static class AuditLogConfig {

        @Bean
        @ConditionalOnMissingBean
        public io.github.biglv666.authkit.observability.AuthKitAuditLogger authKitAuditLogger() {
            return new io.github.biglv666.authkit.observability.AuthKitAuditLogger();
        }
    }

    /** 可选的异步上下文传递：注册默认 TaskDecorator（业务自定义优先） */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "auth-kit.context", name = "propagate-async", havingValue = "true")
    static class AsyncContextConfig {

        @Bean
        @ConditionalOnMissingBean(org.springframework.core.task.TaskDecorator.class)
        public org.springframework.core.task.TaskDecorator authContextTaskDecorator() {
            log.info("[auth-kit] 已注册 AuthContextTaskDecorator（异步上下文透传）");
            return new io.github.biglv666.authkit.context.AuthContextTaskDecorator();
        }
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
        @ConditionalOnMissingBean
        public ManagementTokenProvider managementTokenProvider(AuthKitProperties properties) {
            return new ConfigManagementTokenProvider(properties.getManagement());
        }

        @Bean
        public OnlineSessionController onlineSessionController(AuthManager authManager,
                                                               AuthKitProperties properties) {
            return new OnlineSessionController(authManager,
                    properties.getManagement().getMaxOnlineSessions());
        }

        @Bean
        public FilterRegistrationBean<ManagementTokenFilter> managementTokenFilter(
                AuthKitProperties properties, ManagementTokenProvider tokenProvider) {
            java.util.Collection<String> tokens = tokenProvider.tokens();
            if (tokens == null || tokens.isEmpty()) {
                if (tokenProvider instanceof ConfigManagementTokenProvider) {
                    throw new IllegalStateException(
                            "auth-kit.management.enabled=true 时必须配置 auth-kit.management.auth-token 或 auth-tokens（管理端点令牌）");
                }
                // 自定义动态 Provider 允许启动时为空（例如从配置中心异步加载），但必须显式告警
                log.warn("[auth-kit] 自定义 ManagementTokenProvider 启动时无令牌，管理端点将拒绝所有请求直到提供令牌");
            }
            ManagementTokenFilter filter = new ManagementTokenFilter(
                    properties.getManagement().getBasePath(),
                    properties.getManagement().getAuthHeader(),
                    tokenProvider);
            FilterRegistrationBean<ManagementTokenFilter> registration = new FilterRegistrationBean<>(filter);
            registration.addUrlPatterns("/*");
            registration.setOrder(1);
            return registration;
        }
    }
}
