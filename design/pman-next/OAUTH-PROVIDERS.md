# OAUTH-PROVIDERS

提供方能力调研与适配依据。所有第三方结论必须带官方资料 URL、查证日期与适用版本；
不允许假定两个提供方支持相同流程。T02 已交付的只读检查接口在此登记；
T03 的 OAuth 授权流程调研在后续章节补充。

## 1. 只读身份检查接口（T02 已实现）

实现位置：`rust/crates/pman-core/src/check.rs`（`execute_connection_check`）。

### GitHub

| 项 | 值 |
| --- | --- |
| 端点 | `GET https://api.github.com/user` |
| 官方资料 | https://docs.github.com/en/rest/users/users#get-the-authenticated-user |
| 查证日期 | 2026-09-19 |
| 适用版本 | GitHub REST API（版本标注 2022-11-28） |
| 认证 | `Authorization: Bearer <token>`（classic PAT / fine-grained PAT） |
| 解析字段 | 仅 `login`（作为脱敏显示名）；不解析邮箱、不读取任何私有资源 |
| 失败语义 | 401=凭据失效；403=权限不足（fine-grained token 未含该资源时常见），**不当作凭据过期** |
| 检测条件 | 连接主机为 `api.github.com`，或连接 `provider` 设为 `github` |

### GitLab（gitlab.com 与自托管）

| 项 | 值 |
| --- | --- |
| 端点 | `GET {origin}/api/v4/user` |
| 官方资料 | https://docs.gitlab.com/ee/api/users.html（Retrieve the current user / single user API） |
| 查证日期 | 2026-09-19 |
| 适用版本 | GitLab REST API v4（自托管实例路径一致） |
| 认证 | `Authorization: Bearer <token>`（PAT 或 OAuth access token） |
| 解析字段 | 仅 `username`（作为脱敏显示名） |
| 失败语义 | 401=凭据失效；403=该 token 无 `read_user` 能力，不当作凭据过期 |
| 检测条件 | 主机为 `gitlab.com`/`*.gitlab.com`，或连接 `provider` 设为 `gitlab` |

### 自定义只读路径

通用 API 连接可配置 `check_path`（如 `/health`）。200-299 仅证明该只读路径可用
（api 维度 `ready`，作用域标注），**不**宣称身份已验证；身份维度保持"尚未检查"。
未配置路径的未知服务只报告保存状态（`saved_only`），不发起网络请求。

### E10

E10 使用 `e10::check_session`（独立会话检查，含账号绑定校验），证据经
`finish_e10_evidence` 写入同一契约。该接口属于私有平台，不在此列为通用提供方。

### 检查的统一约束

- 只发 `GET`；禁止用写请求测试权限（回归：`check_requests_are_get_only_with_no_body_side_effects`）。
- 响应经共享代理链脱敏；包含凭据的响应被拦截或脱敏，永不回显。
- 结果只记录证据（`identity_check` / `api_check`），不改策略、不删凭据、
  不递增请求 generation。
- 网络失败/超时保留凭据；401/403/429 映射为不同的可恢复状态。

## 2. OAuth 授权流程（T03，待补充）

> 本节在 T03 实现时填写：每个提供方的授权端点、PKCE/回调限制、
> client secret 部署责任、scope 列表、刷新与撤销能力、回退路径。
> 缺少部署条件的提供方保留明确可用的 Token 路径，不伪造一键 OAuth。
