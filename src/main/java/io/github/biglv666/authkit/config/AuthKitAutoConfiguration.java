package io.github.biglv666.authkit.config;

import io.github.biglv666.authkit.AuthKit;
import io.github.biglv666.authkit.context.CurrentUserArgumentResolver;
import io.github.biglv666.authkit.core.AuthManager;
import io.github.biglv666.authkit.core.TokenResolver;
import io.github.biglv666.authkit.crypto.BCryptPasswordEncoderAdapter;
import io.github.biglv666.authkit.dao.AttemptStore;
import io.github.biglv666.authkit.dao.InMemoryAttemptStore;
import io.github.biglv666.authkit.dao.InMemorySessionDao;
import io.github.biglv666.authkit.dao.RedisAttemptStore;
import io.github.biglv666.authkit.dao.RedisSessionDao;
import io.github.biglv666.authkit.dao.SessionDao;
import io.github.biglv666.authkit.guard.LoginAttemptGuard;
import io.github.biglv666.authkit.interceptor.AuthInterceptor;
import io.github.biglv666.authkit.management.ManagementTokenFilter;
import io.github.biglv666.authkit.management.OnlineSessionController;
import io.github.biglv666.authkit.spi.PasswordEncoder;
import io.github.biglv666.authkit.spi.PermissionProvider;
import io.github.biglv666.authkit.token.RandomTokenGenerator;
import io.github.biglv666.authkit.token.TokenGenerator;
import io.github.biglv666.authkit.webcommon.AuthKitDefaultExceptionHandler;
import io.github.biglv666.authkit.webcommon.AuthKitWebCommonExceptionHandler;
import io.github.biglv666.webcommon.result.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
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
@EnableConfigurationProperties(AuthKitProperties.class)
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
    @ConditionalOnMissingBean
    public AuthManager authManager(SessionDao sessionDao, TokenGenerator tokenGenerator,
                                   AuthKitProperties properties,
                                   ObjectProvider<PermissionProvider> permissionProvider) {
        AuthManager manager = new AuthManager(
                sessionDao,
                tokenGenerator,
                properties.getTimeout().toMillis(),
                properties.getActiveTimeout().toMillis(),
                properties.getMaxSessionsPerDevice());
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

    // ── Web 层 ──

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class AuthKitWebConfig {

        @Bean
        @ConditionalOnMissingBean
        public AuthInterceptor authInterceptor(AuthKitProperties properties, AuthManager authManager,
                                               TokenResolver tokenResolver) {
            return new AuthInterceptor(properties, authManager, tokenResolver);
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
