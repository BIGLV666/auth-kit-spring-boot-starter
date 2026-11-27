# 升级注意事项

## 1.3.0

- 新增可选的 `auth-kit.guard.mode=risk-control`（滑动尝试窗口 + 渐进封禁 5m→15m→1h→6h→24h）。默认仍为 `counter` 固定窗口计数，升级后行为不变，无需迁移；仅在需要连续风控升级时显式开启。
- 新增可观测性（Micrometer/Actuator/审计日志）、异步上下文传递、管理端点多令牌与 SSE 查询参数 token，全部默认关闭或按类路径自动生效，无需迁移。
- **行为修正**：类路径没有 `spring-data-redis` 时，1.2.0 会在启动期因自动装配引用 `RedisConnectionFactory` 而失败；1.3.0 改为正常降级内存，`store=redis` 时仍 fail-fast。升级后无需改配置。
- **并发修正**：同账号并发登录不再互相顶掉导致无有效会话；`max-sessions-per-device=1` 下最终恰好保留一个。
- 管理端点新增 `auth-tokens` 多令牌与 `max-online-sessions`；原 `auth-token` 继续兼容。
- 发布工程：`maven-gpg-plugin` 使用 `settings.xml` 的 `gpg.passphrase` 读取口令。

## 1.2.0

- **OAuth2 第三方登录的 token 投递默认从查询参数改为 fragment**：落地页现在是 `/sso-done#token=...`。前端若仍从 `?token=` 读取，请改为读取 `location.hash`，或临时配置 `auth-kit.oauth2.client.token-delivery=query` 兼容旧逻辑（迁移完成后应移除）。
- 会话 Hash 新增 `expireAt` 字段，旧会话缺少该字段时按原有 TTL 行为兼容，无需数据迁移。
