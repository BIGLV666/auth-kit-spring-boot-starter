# 升级注意事项

## 1.2.0

- **OAuth2 第三方登录的 token 投递默认从查询参数改为 fragment**：落地页现在是 `/sso-done#token=...`。前端若仍从 `?token=` 读取，请改为读取 `location.hash`，或临时配置 `auth-kit.oauth2.client.token-delivery=query` 兼容旧逻辑（迁移完成后应移除）。
- 会话 Hash 新增 `expireAt` 字段，旧会话缺少该字段时按原有 TTL 行为兼容，无需数据迁移。
