# pman 本地协议 v2

这是 Python `pmd` 与后续 Rust/Tauri broker 共用的最小兼容边界。传输可以是当前
`127.0.0.1` HTTP、MCP JSON-RPC，或 Windows named pipe；业务结果字段保持一致。

## 版本与结果包

所有 JSON 结果都包含：

```json
{
  "protocol": "pman",
  "protocol_version": 2,
  "error_code": "ok",
  "ok": true
}
```

`error_code` 是机器可判断的稳定值，`error` 只用于人类可读提示，客户端不得依赖
中文文案做分支。

当前错误码：

| 错误码 | 含义 | 调用方动作 |
|---|---|---|
| `ok` | 请求已执行 | 读取状态码和净化后的响应 |
| `vault_locked` | broker 未解锁 | 提示用户在本地解锁；不要索要主密码 |
| `unknown_site` | 站点别名不存在 | 重新调用 `pm_sites` |
| `site_inactive` | 站点已停用 | 提示用户处理站点 |
| `harness_invalid` | harness 不存在、过期或已吊销 | 停止重试并提示用户 |
| `policy_denied` | 策略拒绝且未生成审批 | 不要绕过策略，提示用户检查本地策略 |
| `rate_limited` | 触发配额 | 等待后重试 |
| `pending_approval` | 等待人工审批 | 保存 `req_id`，调用审批等待接口 |
| `response_blocked` | 返回疑似包含凭据 | 不要尝试绕过；提示用户检查目标响应 |
| `request_failed` | 代理或目标连接失败 | 按网络错误处理 |
| `invalid_request` | 请求字段或组合不符合协议 | 修正参数后再试，不要盲目重试 |
| `scenario_not_found` | 没有场景路由匹配意图和上下文 | 配置路由或补充正确上下文 |
| `scenario_ambiguous` | 多个连接同时匹配 | 补充环境、服务或其他条件，禁止猜账号 |

未知错误码必须按失败处理，不能假设成功。

## HTTP 请求

`POST /v1/http` 的请求体：

```json
{
  "site": "gitlab",
  "method": "GET",
  "path": "/api/v4/projects",
  "capability": "gitlab.projects.read",
  "query": {"owned": "true"},
  "json_body": null,
  "form": null
}
```

`site`、`method`、`path` 是必填字段，`capability` 是可选的稳定业务能力 ID；`query` 可与请求体同时使用，`json_body` 与 `form`
最多选择一种；method 仅支持 `GET/POST/PUT/DELETE/PATCH`，path 不得含控制字符。
凭据只由 broker 从本地 Vault 注入，调用方不得发送 token、Cookie 或密码。

成功响应会包含 `status_code`、净化后的 `headers`，以及 `body_json` 或 `body_text`。
响应头会剥除认证/会话字段；响应体同时按敏感字段和已知凭据值脱敏，仍疑似泄漏时
返回 `response_blocked`。

## 审批

白名单外的精确请求或命中高危方法审批策略时返回：

```json
{
  "ok": false,
  "error_code": "pending_approval",
  "pending_approval": true,
  "req_id": "apr_…",
  "approval_status": "pending"
}
```

批准记录绑定 `harness + site + method + path + HMAC(request)`，成功使用一次后立即
消费，不会永久修改白名单。不同路径、查询参数或请求体必须重新审批；harness token 不能批准、拒绝或查看
审批队列。

AI 只能通过 `GET /v1/approval?id=…` 查询自己创建的请求状态。审批队列、审计、锁定、
解锁和策略修改属于本地人工管理面，由 CLI/桌面端直接访问 Vault。

## 场景与能力

AI 可先调用 `resolve_scenario`（MCP 名称 `pm_resolve_scenario`），传入稳定业务意图和字符串上下文。Broker 只在当前客户端可见、允许 AI 使用的连接中匹配：唯一命中返回连接引用和 `capability`；零条或多条命中均不选择账号。

授权规则可绑定同名 `capability`，并通过 `constraints.query`、`constraints.form`、`constraints.json_body` 限制顶层参数的允许值或 glob。能力规则必须同时满足原有 site/method/path 和全部参数约束；不含 capability 的旧规则继续兼容。

## 兼容规则

- `protocol_version=2` 是当前版本；客户端遇到更高版本应提示升级，不得静默降级。
- 新字段采用可选方式增加；旧客户端可以忽略未知成功字段。
- `error_code` 与 `req_id` 的语义保持向后兼容；中文 `error` 文案可以改变。
- Python 0.3 的 Vault schema v1 会自动迁移为 v2；Rust/Tauri 读取 v2 后只写 v2。
