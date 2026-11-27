# Changelog

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-11-27

### Added

- **risk-control 登录风控**：`guard.mode=risk-control` 支持滑动尝试窗口 + 递增封禁（5m→15m→1h→6h→24h），新增 `RiskControlStore` SPI（内存/Redis）与状态机测试。默认仍为 `counter`，无行为变化。
- **可观测性**：`AuthKitAuditEvent`（登录成功/失败/锁定）、默认审计日志（logger `auth-kit.audit`，不含 token）、可选 Micrometer 指标（`authkit.login` / `authkit.guard.lockouts` / `authkit.session.events`，标签有界）、Actuator 健康检查（Redis ping；内存降级可配置 UP/DOWN）。
- **异步上下文传递**：`AuthContext.wrap(Runnable/Callable)`；`auth-kit.context.propagate-async=true` 时自动注册默认 `TaskDecorator`。
- **管理端点增强**：多令牌 `management.auth-tokens`、`ManagementTokenProvider` SPI（支持热轮换）、在线会话信息补齐（expireAt/rememberMe/remainingSeconds）与条数上限。
- **SSE/EventSource**：可选 `token.query-parameter-name` 从查询参数读取 token（默认关闭；文档标注 query token 泄露风险，优先 Cookie）。

### Fixed

- **无 spring-data-redis 时启动失败**：Redis 相关自动装配按类路径存在性隔离，没有 Redis 依赖时正常降级内存；`store=redis` 时 fail-fast。
- **同账号并发登录互相顶掉**：`SessionDao.runExclusive` + Redis 分布式登录锁，保证 `max-sessions-per-device=1` 下并发登录最终恰好一个有效会话。
- 会话事件监听从单监听器改为多监听器，SSO/指标/审计可同时注册。

### Changed

- `maven-gpg-plugin` 增加 `passphraseServerId=gpg.passphrase`，发布可从 `settings.xml` 读取口令。

## [1.2.0] - 2026-11-06

- JWT 记住我修复；Redis 续期改为 Lua 原子脚本；OAuth2 第三方登录 token 默认 fragment 投递；防爆破命名空间隔离；文档与 CI 对齐。

## [1.1.0] - 2026-09-05

- OAuth2 授权服务器、第三方登录客户端（GitHub/企业微信）与 SSO 合入主模块。

## [1.0.0] - 2026-09-05

- 首个稳定版：不透明 token + 有状态会话、注解鉴权、踢人/顶号、滑动续期、二级认证、JWT 可选模式、管理端点。
