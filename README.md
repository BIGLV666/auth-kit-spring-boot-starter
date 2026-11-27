# auth-kit-spring-boot-starter

[![Maven Central](https://img.shields.io/maven-central/v/io.github.biglv666/auth-kit-spring-boot-starter)](https://central.sonatype.com/artifact/io.github.biglv666/auth-kit-spring-boot-starter) [![CI](https://github.com/BIGLV666/auth-kit-spring-boot-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/BIGLV666/auth-kit-spring-boot-starter/actions/workflows/ci.yml)

轻量级认证鉴权组件：**不透明 token + 有状态会话**，支持踢人下线、同端互斥、滑动续期、登录防爆破。
**不带用户表**——auth-kit 只管认证与校验，用户数据通过 SPI 对接你自己的表。

> 与 Sa-Token 同路线（服务端持有会话状态），但更克制：五条 SPI、五个可选依赖、零配置可跑。
> 与 RuoYi 类平台相反：不内置 user/role/permission 表，不跟业务库打架。

踢人下线、同端互斥、滑动续期、强制登出，本质都要求服务端持有会话状态。JWT 无状态，实现这些只能靠黑名单补丁——用更复杂的机制绕回有状态，还引入密钥管理问题。JWT 模式已作为可选补充（`token.mode=jwt`，取舍见[使用手册第 7 节](docs/USAGE.md#7-jwt-可选模式)）。

## 核心特性

| 能力 | 说明 |
|---|---|
| 登录/登出/登录态 | `AuthKit.login()` 静态门面；会话含 userId、设备、登录/最后活跃时间 |
| token 签发解析 | SecureRandom 64 字符 base64url；Header（Bearer 前缀）/Cookie 双支持 |
| Redis 会话存储 | `SessionDao` SPI；Hash 存会话 + ZSet 反查索引 + 墓碑记录踢出原因 |
| 内存会话降级 | 无 Redis 自动切换（启动 WARN 提示），仅限本地开发 |
| 滑动续期 + 活跃超时 | 活跃时间自动推进；与绝对有效期**两个独立维度**，互不污染 |
| 踢人下线 | 按 userId（可选设备维度）；被踢端收到 KICKED_OUT 专用语义 |
| 同端互斥/多端上限 | `max-sessions-per-device`：1=顶号 / -1=不限 / n=保留最近 n 个 |
| 注解体系 | `@RequireLogin` `@RequirePermission` `@RequireRole`(ALL/ANY) `@AuthIgnore`，类级+方法级取"与" |
| 鉴权拦截器 | 白名单 Ant 匹配、注解解析缓存、软解析（无注解端点带 token 也能注入上下文） |
| @CurrentUser + AuthContext | 参数解析器注入；校验全过后才填充 ThreadLocal（防串号），afterCompletion 强制清理 |
| 五种下线语义 | NO_TOKEN / TOKEN_INVALID / TOKEN_TIMEOUT / KICKED_OUT / BE_REPLACED |
| 异常统一出口 | 有 web-common → Result(40100/40300)；无 → 原生 401/403 |
| BCrypt + PasswordEncoder SPI | 类路径有 spring-security-crypto 自动提供，否则业务自配 |
| 登录防爆破 | `LoginAttemptGuard` 三段式插桩；默认固定窗口计数，可选 risk-control 滑动尝试窗口 + 递增风控（5m→15m→1h→6h→24h） |
| 管理端点 | 在线会话查询/强制下线；静态令牌保护，默认关闭，启用必须配令牌 |
| 记住我 | `login(userId, device, rememberMe)`，remember 会话走 `remember-timeout` 长效期 |
| 二级认证 | `@RequireSafe` + `openSafe/isSafe/closeSafe`，敏感操作 N 分钟免二次验密 |
| JWT 可选模式 | `token.mode=jwt`，HS256 纯 JDK 实现；本地验签 + 墓碑黑名单，踢人/顶号语义不变 |
| 会话并发治理 | `device-max-sessions` 按设备覆盖上限；管理端点支持逐设备踢出 |
| OAuth2 授权服务器 | `/oauth2/authorize` + `/oauth2/token`，authorization_code + refresh_token；**签发的 access_token 就是本组件会话凭证** |
| 第三方登录客户端 | `IdentityProvider` SPI，内置 GitHub / 企业微信；业务只实现"档案 → userId"绑定 |
| 单点登录 | 多应用共享 Redis 会话即 SSO；登出/踢人全局生效 + 会话事件广播 |

## 快速开始

### 1. 引入依赖

```xml
<dependency>
    <groupId>io.github.biglv666</groupId>
    <artifactId>auth-kit-spring-boot-starter</artifactId>
    <version>1.3.0</version>
</dependency>
```

### 2. 实现权限 SPI（唯一必配项）

```java
@Bean
public PermissionProvider permissionProvider() {
    return new PermissionProvider() {
        @Override
        public Set<String> getPermissions(String userId) {
            return permissionMapper.selectCodesByUserId(Long.parseLong(userId)); // 查你自己的表
        }
        @Override
        public Set<String> getRoles(String userId) {
            return roleMapper.selectCodesByUserId(Long.parseLong(userId));
        }
    };
}
```

纯登录制（无权限概念）可不实现——两个方法均有空集默认实现。

### 3. 登录（密码校验由业务完成）

```java
if (passwordEncoder.matches(rawPassword, user.getPassword())) {
    String token = AuthKit.login(user.getId(), DeviceType.APP);
    return Result.ok(Map.of("token", token));
}
```

### 4. Controller 鉴权

```java
@RequirePermission(value = {"order:delete", "order:admin"}, mode = AuthMode.ANY)
@DeleteMapping("/order/{id}")
public void delete(@PathVariable Long id) { ... }

@GetMapping("/me")
public Result<ProfileVO> me(@CurrentUser AuthUser user) {
    return Result.ok(profileService.of(user.getUserIdAsLong()));
}
```

前端携带：`Authorization: Bearer {token}`。完整 API 与拦截语义见[使用手册](docs/USAGE.md)。

## 核心配置

零配置可跑（默认：Authorization + Bearer、30d 绝对有效期 + 7d 活跃超时、顶号、防爆破 5 次/15m、白名单 `/login` 与 `/actuator/**`）。常用定制：

```yaml
auth-kit:
  token:
    timeout: 7d
    active-timeout: 1d
  session:
    max-sessions-per-device: 1
  whitelist:
    - /login
```

防爆破默认使用固定窗口计数；需要「连续风控升级」时启用 `guard.mode=risk-control`（滑动尝试窗口 + 递增封禁），常用参数如下，完整项见[配置全参考](docs/CONFIGURATION.md)：

```yaml
auth-kit:
  guard:
    mode: risk-control
    attempt-window: 5m
    fail-max-attempts: 5
```

全部配置项、管理端点与扩展点替换见[配置全参考](docs/CONFIGURATION.md)；OAuth2 / SSO 配置见[使用手册第 9 节](docs/USAGE.md#9-oauth2--sso)。

## 文档导航

| 文档 | 内容 |
|---|---|
| [使用手册](docs/USAGE.md) | 拦截语义、API 逐个讲解、OAuth2/SSO、下线语义、完整 API 速查 |
| [配置全参考](docs/CONFIGURATION.md) | 全部配置项、环境示例、管理端点、五条 SPI 扩展点 |
| [集成指南](docs/INTEGRATION.md) | 与四件套的咬合方式、PaperWise 从 JWT 迁移实战 |
| [FAQ 与已知限制](docs/FAQ.md) | 常见问题、使用限制、边界说明 |
| [升级注意事项](docs/UPGRADE.md) | 版本间行为变更与迁移步骤 |
| [演示工程](examples/auth-kit-demo/README.md) | 登录/注解/二级认证/顶号一条龙 curl 演示 |

## License

Apache License 2.0
