# OAUTH-PROVIDERS

提供方能力调研与适配依据。所有第三方结论必须带官方资料 URL、查证日期与适用版本；
不允许假定两个提供方支持相同流程。T02 已交付的只读检查接口在此登记；
T03 的 OAuth 授权流程见第 2 节。实现代码：`rust/crates/pman-core/src/oauth.rs`、
`desktop/src-tauri/src/oauth_login.rs`、`desktop/src/ConnectionLibrary.tsx`
（`OAuthDialog`）。

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

## 2. OAuth 授权流程（T03 已实现）

原则：只实现提供方正式支持且**无需 client secret** 的流程；应用注册由用户
在提供方完成，pman 只保存 `client_id`（`ConnectionDetails.oauth_client_id`，
serde 默认，旧库无此字段）。client secret 永不进入桌面、前端或模型上下文；
需要机密客户端的流程一律不提供，保留 Token 路径。

### 2.1 GitLab（gitlab.com 与自托管）—— 授权码 + PKCE

| 项 | 值 |
| --- | --- |
| 流程 | Authorization Code with PKCE（S256），公开客户端 |
| 官方资料 | https://docs.gitlab.com/ee/api/oauth2.html |
| 查证日期 | 2026-09-19 |
| 端点 | 授权 `{origin}/oauth/authorize`；令牌 `{origin}/oauth/token` |
| client secret | **不需要**（官方：PKCE 免 secret 完成交换） |
| 回调 | `http://127.0.0.1:9867/callback`（固定端口，需用户在应用注册中精确填写；GitLab 要求 redirect_uri 精确匹配，端口不可通配的版本也兼容此做法） |
| 默认 scope | `read_user`（最小只读；用户可改 `oauth_scope`） |
| 令牌 | access token 约 2 小时（`expires_in`），返回 refresh token；**刷新会轮换两枚令牌**（旧 refresh 失效）→ pman 原子化写回 secret |
| 刷新 | `POST /oauth/token`，`grant_type=refresh_token`，带 client_id + refresh_token + redirect_uri，无 secret |
| 撤销 | `{origin}/oauth/revoke`；文档示例带 client_secret，公开客户端的撤销行为未确证 —— v1 未实现程序化撤销，用户在 GitLab 应用设置中撤销（已登记为边界） |
| 注册责任 | 用户在 GitLab → 用户设置 → 应用 中创建应用，填入回调地址 |

### 2.2 GitHub —— 设备授权流程

| 项 | 值 |
| --- | --- |
| 流程 | OAuth App Device Flow（无 secret、无 PKCE；PKCE 仅官方 Web 流支持，且 Web 流交换仍需 secret → 不采用） |
| 官方资料 | https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps |
| 查证日期 | 2026-09-19 |
| 端点 | `POST https://github.com/login/device/code`（client_id+scope）；轮询 `POST https://github.com/login/oauth/access_token`（client_id+device_code+`grant_type=urn:ietf:params:oauth:grant-type:device_code`） |
| client secret | **不需要**（官方明确设备流无需 secret） |
| 轮询 | 按 `interval` 秒轮询；`slow_down` 追加 5 秒；`authorization_pending` 继续；`expired_token`（默认 900 秒）停止；`access_denied` 视为取消 |
| 默认 scope | `read:user`（最小只读身份；用户可改 `oauth_scope`） |
| 令牌 | 默认长期有效；启用到期后 `expires_in` + refresh token（轮换），pman 按同一原子刷新路径处理 |
| 注册责任 | 用户在 GitHub → Settings → Developer settings → OAuth Apps 注册应用（无需回调地址的设备流应用） |

### 2.3 通用提供方扩展接口

`desktop/src-tauri/src/service.rs::PendingOAuthFlow` 提供
`info()/cancellation()/cancel()/complete(timeout)` 四个语义；新提供方实现
`begin/complete`（含 state/PKCE、回调校验、超时取消、身份获取）后接入同一套
桌面命令（`oauth_begin/complete/cancel/status/refresh`）。前端只拿
`session_id`、`kind`、`url`、`user_code`、`expires_at`（`OAuthStart`），
以及完成后的脱敏账号名。

### 2.4 安全不变量（回归测试位置）

| 不变量 | 测试 |
| --- | --- |
| state 一次性、伪造 state 先于令牌交换被拒绝 | `wrong_state_is_rejected_before_any_token_exchange` |
| PKCE S256：verifier 与 authorize challenge 绑定，令牌请求不带 secret | `gitlab_flow_success_binds_pkce_state_and_identity` |
| 提供方拒绝（error 回调）→ 取消语义，不交换令牌 | `provider_denied_callback_is_reported_as_cancelled` |
| 流程可取消、超时停止 | `cancelling_the_flow_stops_completion`、`missing_callback_times_out` |
| 回调不可重放（流程被消费，监听器关闭） | `a_consumed_flow_rejects_duplicate_callbacks` |
| 账号绑定：换账号的登录被拒绝且不写入令牌 | `oauth_login_binds_account_and_a_second_account_is_rejected` |
| 刷新：form 含 grant_type/refresh_token、无 secret、轮换原子写回 | `refresh_rotates_tokens_atomically_and_requires_configuration`、`github_device_flow_polls_until_success_and_fetches_identity` |
| 设备码/令牌不进入 `OAuthStart` 序列化 | `oauth_start_information_never_contains_secret_material` |
| epoch/generation 绑定：锁定、暂停、连接变化使旧回调失效 | 桌面 `oauth_begin/complete` 复用 `ensure_epoch` + generation 校验（与 e10 流程一致） |

### 2.5 未验收边界

- 真实 GitHub / GitLab.com / 自托管 GitLab 登录需用户注册应用并由本人完成
  授权，属人工验收项（见 ACCEPTANCE.md），不以模拟测试替代。
- GitLab 程序化令牌撤销（公开客户端无 secret 的 revoke 行为）未确证、未实现。
- GitHub 令牌到期的自动检测依赖 `oauth_token_expires_at` 字段；当前版本在
  检查返回 401 时提示刷新/重新登录，不做自动静默刷新。
