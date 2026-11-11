# FAQ 与已知限制

## FAQ

**Q：和 Sa-Token 的区别？**

同路线（不透明 token + 服务端会话），本组件更小：核心仅会话模型 + 注解鉴权 + 防爆破，无 OAuth2/二级认证等大模块；且与自家 web-common 的 Result 体系原生咬合。

**Q：为什么不做用户表/注册登录接口？**

starter 内置用户表会跟业务库打架（字段、加密方式、表名都可能冲突）。auth-kit 只管"登录态与校验"，账号体系归业务。

**Q：token 会话在 Redis 里怎么存的？会序列化整个对象吗？**

不会。Hash 存 5 个简单字段，无序列化框架依赖，无反序列化漏洞面。

**Q：权限数据每次校验都查库吗？**

是的（组件不缓存，变更实时生效）。热路径建议在 PermissionProvider 实现里加短 TTL 本地缓存。

**Q：能不引入 Redis 吗？**

能。自动降级内存实现（启动有 WARN），仅适合本地开发/单实例，重启会话丢失。

**Q：异步线程里怎么拿当前用户？**

ThreadLocal 不跨线程传递。提交任务前先 `AuthKit.getLoginId()` 取出，作为参数传给异步任务。

## 已知限制

- 设备标识不能包含 `|`（Redis 索引分隔符）
- `@Async` / 自建线程池场景 ThreadLocal 需手动传递
- 生产环境必须配 Redis，内存实现仅限开发
- token 明文作会话 key，如需抗 Redis 泄露可二开 SessionDao 做摘要存储

## 相关文档

- 下线语义（NO_TOKEN / TOKEN_INVALID / TOKEN_TIMEOUT / KICKED_OUT / BE_REPLACED）与前端处理见 [USAGE.md 第 10 节](USAGE.md#10-下线语义对照前端处理指南)。
- 配置项与扩展点见 [CONFIGURATION.md](CONFIGURATION.md)。
- 1.2.0 升级注意事项见 [UPGRADE.md](UPGRADE.md)。
