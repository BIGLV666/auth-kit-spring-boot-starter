# 配置全参考

前缀 `auth-kit`，全部有默认值，零配置可跑。配置类：`io.github.biglv666.authkit.config.AuthKitProperties`。

## 完整配置项

```yaml
auth-kit:
  enabled: true                        # 组件总开关

  token:
    header-name: Authorization         # 读取 token 的请求头名称
    cookie-name: ""                    # Cookie 兜底读取；空=不读 Cookie。
                                       # Header 缺失时读此 Cookie（双端场景：App 用 Header、浏览器用 Cookie）
    prefix: Bearer                     # 前缀剥离，大小写不敏感，兼容 "Bearer"/"bearer"；空=裸 token
    timeout: 30d                       # 会话绝对有效期。登录时一次确定，任何活跃都不延长。
                                       # 支持 30d/12h/30m/60s 等 Spring Duration 格式
    active-timeout: 7d                 # 活跃超时（滑动续期维度）：连续 N 无请求即失效；0=关闭。
                                       # 与 timeout 独立：会话实际寿命 = min(登录+timeout, 最后活跃+active-timeout)
    style: random-64                   # token 策略标识。V1 仅支持 random-64；
                                       # 自定义形态请注册 TokenGenerator Bean（此项仅作声明）
    mode: opaque                       # opaque（默认，会话读取校验，全功能）
                                       # jwt（签名 JWT 自校验：无滑动续期/实时活跃数据，登出踢人靠墓碑黑名单）
    jwt-secret: ""                     # mode=jwt 时必填，HS256 密钥，至少 16 字符（建议 32+）
    remember-timeout: 30d              # 记住我会话的绝对有效期（login(..., rememberMe=true) 时生效）
    query-parameter-name: ""           # 可选查询参数名（如 access_token）；默认空=不读。
                                       # 仅供 EventSource/SSE 等不能设 Header 的场景；query token 会进日志/Referer，优先 Cookie

  session:
    store: auto                        # auto：有 RedisConnectionFactory 用 Redis，否则内存（WARN 日志）
                                       # redis：强制 Redis，缺 Redis 启动报错
                                       # memory：强制内存（仅本地开发/单实例）
    max-sessions-per-device: 1         # 同端会话上限。1=顶号；-1=不限；n=保留最近 n 个（最旧优先驱逐，标记 BE_REPLACED）
    device-max-sessions:               # 按设备覆盖上限，未命中回退 max-sessions-per-device
      APP: -1                          # 例：App 允许多端
      WEB: 1                           # 例：浏览器互斥
    kicked-out-message: 您已在其他设备登录  # 被顶下线（BE_REPLACED）时前端收到的文案
    key-prefix: auth-kit               # Redis key 前缀；会话、墓碑、索引、防爆破计数统一使用

  guard:
    mode: counter                      # counter（默认，固定窗口计数）| risk-control（滑动尝试窗口 + 递增风控）
    enabled: true                      # 防爆破开关（守卫 Bean 是否注入计数逻辑）
    fail-max-attempts: 5               # counter：最大连续失败次数；risk-control：每个尝试窗口最大次数
    lock-duration: 15m                 # counter 专用：锁定时长 = 计数窗口

    # 以下仅 risk-control 模式生效
    attempt-window: 5m                 # 滚动尝试窗口：窗口内最多尝试 fail-max-attempts 次
    lockout-durations:                 # 连续风控升级档位，最后一档为封顶
      - 5m
      - 15m
      - 1h
      - 6h
      - 24h
    lockout-reset-interval: 6h         # 上一次风控结束后的静默期，超过则连续风控次数清零
    state-ttl: 31h                     # 带风控历史的状态过期时间；实际 TTL 至少覆盖最长风控+静默期+窗口
    reset-on-success: true             # 成功登录清空尝试窗口，不清连续风控次数

  safe:
    duration: 5m                       # 二级认证（@RequireSafe）通过后的免密窗口

  whitelist:                           # Ant 风格放行路径，命中则完全跳过 auth-kit（不解析 token）
    - /login
    - /actuator/**

  management:
    enabled: false                     # 管理端点总开关（默认关闭）
    auth-token: ""                     # 单令牌（兼容旧配置）；auth-token 与 auth-tokens 至少一个非空
    auth-tokens: []                    # 多令牌：任一匹配即通过，便于灰度/轮换。自定义 ManagementTokenProvider Bean 可热轮换
    auth-header: X-Auth-Kit-Token      # 令牌请求头名称
    base-path: /auth-kit               # 管理端点基础路径（按路径段边界匹配，不会误伤 /auth-kit-xxx）
    max-online-sessions: 200           # 在线会话查询单次最多返回条数（超出截断，按登录时间倒序）

  # 异步上下文传递（默认关闭）。开启后注册默认 TaskDecorator，Spring 线程池任务可读到 AuthContext
  context:
    propagate-async: false

  # 可观测性；Micrometer/Actuator 都是可选依赖，类路径没有时自动跳过
  observability:
    audit-log: true                    # 默认审计日志（logger: auth-kit.audit；不含 token）
    metrics: true                      # Micrometer 指标（存在 MeterRegistry 时生效）
    health: true                       # Actuator 健康检查（存在 HealthIndicator 时生效）
    memory-store-health-up: true       # 内存会话时健康状态；生产建议 false，让降级暴露为 DOWN

  oauth2:                              # 授权服务器与第三方登录默认全关
    server:
      enabled: false
      login-page: /login               # 未登录访问 authorize 时跳转的业务登录页
      code-ttl: 5m                     # 授权码有效期
      refresh-ttl: 30d                 # 刷新令牌有效期
      clients:
        app1:
          client-secret: "app1-secret" # 仅支持机密客户端
          redirect-uris: [ "https://app1.example/cb" ]   # 精确匹配，防开放重定向
          scopes: [ "profile" ]        # 空=不校验 scope
    client:
      enabled: false
      success-redirect: /sso-done      # 登录成功落地页
      token-delivery: fragment         # fragment（默认，token 不进服务端日志/Referer）| query（兼容旧前端）
      providers:
        github:
          client-id: xxx
          client-secret: xxx
          redirect-uri: https://your-app/oauth2/callback/github
        wecom:
          corp-id: ww-xxx
          corp-secret: xxx
          agent-id: "1000002"
          redirect-uri: https://your-app/oauth2/callback/wecom
```

## 配置项 → 生效位置速查

| 配置 | 读取者 |
|---|---|
| token.header-name / cookie-name / prefix / query-parameter-name | `TokenResolver`（拦截器提取 token） |
| token.timeout / active-timeout / remember-timeout | `AuthManager`（登录与校验） |
| token.mode / jwt-secret | 自动装配（`OpaqueTokenCodec` / `JwtTokenCodec`） |
| session.store / key-prefix | 自动装配（SessionDao/AttemptStore/SafeStore/RiskControlStore 选择） |
| session.max-sessions-per-device / device-max-sessions | `AuthManager.evictOverflowSessions` / `maxSessionsFor` |
| session.kicked-out-message | web-common 异常适配器（BE_REPLACED 文案） |
| guard.* | `LoginAttemptGuard`（counter / risk-control 两种模式，key 同样使用 `key-prefix`） |
| safe.duration | `AuthManager`（`@RequireSafe` 免密窗口） |
| whitelist | `AuthInterceptor`（AntPathMatcher） |
| management.* | `ManagementConfig` / `ManagementTokenFilter` / `OnlineSessionController` |
| context.propagate-async | 自动装配（`AuthContextTaskDecorator`） |
| observability.* | `AuthKitMetrics` / `AuthKitHealthIndicator` / `AuthKitAuditLogger` |
| oauth2.* | OAuth2 自动装配 / 授权服务器 / 第三方登录客户端 |

## 管理端点 API

启用 `auth-kit.management.enabled=true` 并配置 `auth-token` 或 `auth-tokens` 后（多令牌任一匹配即可；建议通过环境变量/配置中心注入，不要写进仓库）：

### GET {base-path}/online

查询指定用户的在线会话（token 脱敏为前 8 位）。

```
GET /auth-kit/online?userId=10001            # 全部设备
GET /auth-kit/online?userId=10001&device=APP # 指定设备
X-Auth-Kit-Token: {auth-token}

200 OK
[{"token":"jn648VAK****","userId":"10001","device":"APP",
  "loginTime":1788572683177,"lastActiveTime":1788572683177,
  "expireAt":1788575683177,"rememberMe":false,"remainingSeconds":2999}]
```

结果按登录时间倒序；超过 `management.max-online-sessions`（默认 200）时截断。

### DELETE {base-path}/online/{userId}

强制下线（不写墓碑，旧端收到 TOKEN_INVALID）。幂等，对不存在会话返回成功。

```
DELETE /auth-kit/online/10001?device=APP     # device 可选
X-Auth-Kit-Token: {auth-token}

200 OK
{"success":true,"userId":"10001"}
```

令牌校验失败一律 `401 {"code":40100,"message":"unauthorized"}`（不回显失败细节，防探测）。

## 扩展点：注册 Bean 替换默认实现

| SPI | 职责 | 默认实现 | 替换方式 |
|---|---|---|---|
| `SessionDao` | 会话存储 | Redis（自动）/内存（降级） | 注册同类型 Bean |
| `AttemptStore` | 失败计数 | Redis（自动）/内存（降级） | 注册同类型 Bean |
| `TokenGenerator` | token 形态 | SecureRandom 64 字符 | 注册同类型 Bean |
| `PermissionProvider` | 权限数据源 | 无（业务必配） | 注册同类型 Bean |
| `PasswordEncoder` | 密码编码 | BCrypt（需 security-crypto） | 注册同类型 Bean |

所有默认实现都挂了 `@ConditionalOnMissingBean`，定义同类型 Bean 即全量替换：

### SessionDao（会话存储）

```java
/**
 * 契约见 {@link io.github.biglv666.authkit.dao.SessionDao}：
 * token 会话为唯一真源；索引允许脏读；墓碑幂等；所有方法对不存在 key 静默容错。
 * 参考实现：RedisSessionDao / InMemorySessionDao
 */
@Bean
public SessionDao mySessionDao() {
    return new MyDatabaseSessionDao();  // 例如落库存储、多级缓存等
}
```

### AttemptStore（失败计数）

```java
@Bean
public AttemptStore myAttemptStore() {
    return new MyAttemptStore();  // incr/get/clear 三方法，参考 RedisAttemptStore
}
```

### RiskControlStore（风控状态，risk-control 模式）

```java
@Bean
public RiskControlStore myRiskControlStore() {
    return new MyRiskControlStore();  // check/recordSuccess/clear；check 必须保证同 key 原子性
}
```

## risk-control 模式语义

`mode: risk-control` 下，窗口统计的是**所有尝试**，不是仅失败：

1. `check(identifier)` 原子占用一次尝试额度；未达上限放行，达到上限直接触发/返回风控。
2. 任意滚动 `attempt-window` 内最多 `fail-max-attempts` 次尝试，并发下也不会超限。
3. 触发风控后，按连续风控次数选择 `lockout-durations` 档位；连续次数在
   “上一次风控结束 + `lockout-reset-interval`” 内再次触发时递增，否则从第一档重新开始。
4. 风控期间 `check` 一律拒绝，`LoginLockedException.remainingMillis` 返回真实剩余时间。
5. 成功登录按 `reset-on-success` 清空尝试窗口；连续风控次数只由静默期或 `clear()` 重置。
6. `recordFailure()` 在此模式下为 no-op（尝试已在 `check()` 中计数），现有三段式业务代码无需改动。

状态 key 为 `{key-prefix}:risk:<identifier>`，与 counter 模式的
`{key-prefix}:attempt:<identifier>` 隔离，切换模式不会出现 Redis 类型冲突。
内存实现为单实例，会周期性清理过期状态并限制状态总数；Redis 实现使用单 key Lua 脚本保证原子性，
要求各实例时钟同步。为降低随机用户名扫描造成的内存压力：未触发风控的普通尝试状态 TTL 为
`max(2 × attempt-window, 1m)`，只有带风控历史的状态才使用 `state-ttl`。生产环境仍建议配合
网关限流、Redis `maxmemory` 与监控。

### TokenGenerator（token 形态）

```java
@Bean
public TokenGenerator prefixedTokenGenerator() {
    return () -> "ak_" + UUID.randomUUID().toString().replace("-", "");
}
```

### PermissionProvider（权限数据源，业务必配）

```java
@Bean
public PermissionProvider permissionProvider() {
    return new PermissionProvider() {
        @Override
        public Set<String> getPermissions(String userId) {
            return permissionMapper.selectCodesByUserId(Long.parseLong(userId));
        }
        @Override
        public Set<String> getRoles(String userId) {
            return roleMapper.selectCodesByUserId(Long.parseLong(userId));
        }
    };
}
```

两个方法均有空集默认实现，纯登录制项目可不实现。**未配置此 Bean 时权限/角色校验一律拒绝（fail-closed）**，纯登录制不受影响。

### PasswordEncoder（密码编码）

默认：类路径有 spring-security-crypto 时自动提供 BCrypt。没有时必须自配：

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new PasswordEncoder() {
        public String encode(CharSequence raw) { return myHash(raw); }
        public boolean matches(CharSequence raw, String encoded) { return myVerify(raw, encoded); }
    };
}
```

## 环境示例

### 本地开发（零 Redis）

什么都不配。启动日志出现 `未检测到 Redis，会话降级为内存存储` 即为正常，重启后会话丢失。

### 生产（Redis + 顶号 + 防爆破）

```yaml
auth-kit:
  token:
    timeout: 7d
    active-timeout: 1d
  session:
    max-sessions-per-device: 1
```

### 多环境共用 Redis

```yaml
auth-kit:
  session:
    key-prefix: auth-kit-prod   # 区分 dev/prod 的会话命名空间
```

### 多端差异化上限

全局上限用 `max-sessions-per-device`；需要「App 允许多端、Web 互斥」时用 `device-max-sessions` 按设备覆盖：

```yaml
auth-kit:
  session:
    max-sessions-per-device: 1
    device-max-sessions:
      APP: -1
      PAD: -1
      WEB: 1
```

管理端点（`/auth-kit/online`）支持按设备查询与逐个踢出。业务侧若用不同 device 字符串区分终端（如 `APP-iPhone15` / `APP-Pad`），也可直接按这些值覆盖。
