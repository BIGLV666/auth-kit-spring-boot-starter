# auth-kit-demo

auth-kit 最小演示工程。启动：

```bash
cd examples/auth-kit-demo
mvn spring-boot:run   # 需先 mvn install 父工程（auth-kit 1.0.0）
```

本机有 Redis 自动启用；没有则降级内存会话（启动日志有 WARN 提示）。

## 演示流程

```bash
# 1. 登录（alice 带记住我）
curl -X POST "http://localhost:8081/login?username=alice"
# → {"token":"...","rememberMe":true}

TOKEN=粘贴上面的token

# 2. 游客/登录态差异化
curl "http://localhost:8081/feed"
curl "http://localhost:8081/feed" -H "Authorization: Bearer $TOKEN"

# 3. 登录态 + @CurrentUser
curl "http://localhost:8081/me" -H "Authorization: Bearer $TOKEN"

# 4. 权限校验（alice 有 order:delete → 通过；bob 登录后调用 → 403）
curl -X POST "http://localhost:8081/order/delete" -H "Authorization: Bearer $TOKEN"

# 5. 二级认证（直接调用 → 403"需要安全验证"；开启后 → 通过）
curl -X POST "http://localhost:8081/safe/change-password" -H "Authorization: Bearer $TOKEN"
curl -X POST "http://localhost:8081/safe/open" -H "Authorization: Bearer $TOKEN"
curl -X POST "http://localhost:8081/safe/change-password" -H "Authorization: Bearer $TOKEN"

# 6. 顶号：再登录一次 alice，旧 token 立即 401"您已在其他设备登录"
curl -X POST "http://localhost:8081/login?username=alice"
curl "http://localhost:8081/me" -H "Authorization: Bearer $TOKEN"
```
