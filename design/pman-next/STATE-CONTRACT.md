# 状态契约（STATE-CONTRACT）

本文固定 pman 连接状态的字段来源、消费方、转换规则、稳定错误码与迁移边界。
对应任务：GLM-5.3-TODO T01。实现代码：`rust/crates/pman-core/src/status.rs`、
`desktop/src-tauri/src/backend.rs`（`connection_status` / `list_sites`）、
`desktop/src/connections.ts`、`desktop/src/ConnectionLibrary.tsx`（`StatusPanel`）、
`desktop/src/api.ts`（`errorCodeInfo`）。

规则：任何"未知/未发生"的状态必须显示为**尚未检查**，不得默认为健康；
保存、身份已验证、授权已保存、本机代理检查通过、真实 AI 调用成功是**不同证据**，
不得合并为一个"已连接"。

## 1. 现有数据盘点（字段来源 / 消费方 / 迁移规则）

### 1.1 SiteSummary（`sites` 表，`vault.rs`）

| 字段 | 来源 | 消费方 | 说明 |
| --- | --- | --- | --- |
| `id`, `alias`, `name` | `add_site` 写入，别名唯一 | 书架、详情、活动、CLI `sites` | 显示名优先 name |
| `site_url` | `add_site` / `update_site_metadata`（去尾 `/`） | 代理 `build_url`、详情、origin 校验 | 改地址触发 `revoke_connection_grants` |
| `auth_type` | 创建时固定（`AUTH_TYPES`） | 代理 `inject_auth`、UI 类型标签 | password 类型永不向 AI 开放 |
| `status` | 默认 `active`；永不因检查改写 | broker `authorize`（非 active 拒绝）、书架 | 检查结果不写这里，写 details.extra |
| `expires_at` | 创建/更新凭据时设置 | `is_expired` 判过期 | 过期=凭据维度，不删除凭据 |
| `last_used_at` | broker 成功响应后 `touch_site` | 书架"最近使用" | 真实调用证据之一 |
| `secret_cipher`/`dek_wrapped` | 加密列 | 仅核心解密 | 永不出现在任何 Summary |

### 1.2 ConnectionDetails（`connection_details` 表，`workspace.rs`）

| 字段 | 来源 | 消费方 | 说明 |
| --- | --- | --- | --- |
| `ai_enabled` | `grant_connection_clients` 置 true；改账号/地址时置 false | broker `authorize`（false 拒绝）、UI | 缺行时默认 true（旧版兼容语义） |
| `account`/`environment`/`tenant` | 详情编辑、E10 登录写入 | 场景解析、授权上下文校验 | 变化即撤销旧授权 |
| `scenarios` | 详情编辑 | `resolve_scenario` | — |
| `extra` | 自由 JSON | 见下 | **检查证据存放处** |

`extra` 内约定键（全部 serde 默认，旧库可缺省）：

| 键 | 写入方 | 消费方 |
| --- | --- | --- |
| `status`, `checked_at` | 旧版 `e10_check`（保留写入兼容） | 书架 `statusLabel`、legacy 证据读取 |
| `identity_check` | `Vault::record_check_evidence(identity)` | 状态契约 identity 维度 |
| `api_check` | `Vault::record_check_evidence(api)` | 状态契约 api 维度 |

`CheckEvidence` 结构：`state`、`checked_at`、`message`、`error_code`、`context`
（账号上下文指纹 = sha256(site_url|account|tenant|environment) 前 16 hex）、
`provider`、`account`（远端返回的**脱敏显示名**，如登录名）、`scope`（检查实际证明的内容）。
记录证据**不递增 generation、不改策略、不改账号绑定**（回归测试
`evidence_recording_does_not_invalidate_inflight_requests`）。

### 1.3 ClientSummary（`native_clients` 表，`workspace.rs`）

| 字段 | 来源 | 消费方 | 说明 |
| --- | --- | --- | --- |
| `id`, `name`, `kind` | `client_pair`（桌面，唯一配对入口） | 配置写入、授权选择 | 显示名≠身份；配对身份是 DPAPI 保护的 `.cap` 文件 |
| `harness` | 配对时指定 | 策略归属、活动记录 | 同一 harness 可有多个客户端记录 |
| `paired` | `revoked_at IS NULL` 派生 | UI 筛选 | — |
| `last_used_at` | `authenticate_client` 成功 | AI 工具页 | — |
| `expires_at`/`revoked_at` | 配对/撤销 | 身份校验 | 撤销同时清空 `proof_hash` |

### 1.4 HarnessSummary（`harnesses` 表）

| 字段 | 来源 | 消费方 | 说明 |
| --- | --- | --- | --- |
| `policy` | `set_policy` / `add_allow_rule` / `grant_connection_clients` / `approve_persistently` | broker `authorize`、UI 授权列表 | 唯一的授权事实来源 |
| `revoked_at`/`expires_at` | 旧版 token 管理 | `authenticate_legacy_token`、broker | — |

策略规则字段（`policy.rs`）：`site`、`methods`、`paths`、`expires_at`、
`require_approval`、`capability`、`constraints`。整连接授权 =
全部七种方法 + `/**` + `require_approval:false` + 无 capability/constraints/到期
（`connections.ts::wholeConnection`）。**明确拒绝与既有更严格限制不会被整连接授权删除**。

### 1.5 生命周期状态（`lifecycle.rs` / `service.rs`）

| 状态 | 载体 | 影响 | 不可混淆 |
| --- | --- | --- | --- |
| 管理界面已锁定 | `ManagementState.authenticated`（内存，重启即锁定） | 仅管理命令拒绝 | **不停止**已授权 API 调用 |
| AI 服务已暂停 | `PersistentState.service_paused`（持久化） | broker 直接 `vault_locked` | 只能显式恢复 |
| 保险库已解锁 | `Vault.kek` | 可解密凭据 | 与管理认证独立（`verify_password` 不解锁） |
| 闲置锁定 | `idle_lock` | 仅管理界面 | 不暂停服务 |

## 2. 五维状态模型

计算入口：`Vault::connection_status(alias)` / `connection_statuses()`（一次遍历，
供 `list_sites` 批量附带 `dimensions`）。桌面命令 `connection_status` 额外合并
`service` 段（`management_locked` / `service_paused` / `service_running`）。

| 维度 | 含义 | 证据来源 | 状态码 |
| --- | --- | --- | --- |
| `credential` 凭据保存 | 凭据是否安全存放、是否过期 | 保险库本身（无需网络） | `saved` / `expired` / `inactive` |
| `identity` 身份验证 | 远端只读接口确认账号 | `identity_check` 证据（旧版 `extra.status` 兼容读取） | `unchecked` / `verified` / `unauthorized` / `forbidden` / `rate_limited` / `timeout` / `network_error` / `invalid_response` / `stale` / `not_available` |
| `api` 接口可用性 | AI 经本机代理使用此连接的能力 | 授权存在性 + `api_check` 证据 + 审计日志中最近真实调用（标注证据类型 `grants`/`check`/`usage`） | `not_granted` / `paused` / `client_invalid` / `unchecked` / `restricted` / `ready` / `unauthorized` / `forbidden` / `rate_limited` / `timeout` / `network_error` / `invalid_response` / `stale` / `not_available` |
| `web` 网页操作 | AI 网页通道 | 当前固定 `not_available`（T05 交付后按 BROWSER-CONTRACT.md 扩展） | `not_available` |
| `clients` 客户端授权 | 哪些 AI 客户端被允许 | 策略 + 客户端配对状态（harness 有效且其配对客户端至少一个有效，或为 legacy token 身份） | `none` / `granted` / `invalid` / `not_available` |

每个 `DimensionStatus`：`state`、`label`（中文显示，由 Rust 计算而不是 UI 猜测）、
`detail`、`checked_at`（可空=尚未检查）、`error_code`、`recovery`（恢复动作文案）、
`evidence`（`policy` / `grants` / `check` / `usage`）。

### 2.1 关键转换规则

- **陈旧证据**：证据 `context` 指纹 ≠ 当前指纹（账号/地址/环境变化）→ 显示
  `stale`（检查结果已过期），错误码 `account_context_changed`，绝不显示为当前结果。
  旧版证据（无 context）按现状显示，行为与旧版一致。
- **401 ≠ 过期 ≠ 403**：401 → 凭据被拒（恢复：重新登录/更新凭据）；403 → 权限不足，
  **不当作凭据过期**（恢复：确认服务端账号权限）；429 → 限流；网络失败 → 保留凭据。
- **检查失败不撤销授权**：证据只写 `extra`，不触碰策略；已保存的授权保持有效。
- **真实调用证据**：来自 `audit_log`（`status_code` 非空的最近一条该站点记录），
  标注"最近真实 AI 调用"；显式 `api_check` 证据优先于 usage 证据。
- **限制可见**：整连接授权与 deny/审批规则并存时，api 维度显示
  `restricted`（已授权 · 有限制），不宣称无条件免审批。
- **password 类型**：所有 AI 相关维度 `not_available`；`credential` 仍显示已保存。

### 2.2 验收矩阵（回归测试位置）

| 场景 | 预期 | 测试 |
| --- | --- | --- |
| 已保存但未检查 | identity/api = `unchecked`「尚未检查」，无任何"已连接" | core `saved_but_unchecked_reports_unchecked_dimensions_without_inventing_evidence` + UI `missing status evidence…` |
| 代理通过但远端 401 | identity = `unauthorized`「身份验证失败(401)」+ 恢复动作；api 不受牵连 | core `proxy_reached_but_remote_401_is_distinct_from_unchecked` + UI `status dimensions render separate evidence…` |
| 已授权但客户端撤销 | clients = `invalid`，api = `client_invalid` + 修复动作 | core `authorized_but_revoked_client_is_distinct_and_requires_repair` + UI `invalid or revoked client grants…` |
| 管理锁定但 API 可用 | 状态证据不变、`service_running=true`、管理命令被拒 | desktop `management_lock_neither_changes_connection_evidence_nor_stops_api`（另见既有 `locked_management_keeps_real_authorized_requests_running`） |
| 账号变化后旧证据 | identity = `stale` + `account_context_changed` | core `stale_evidence_after_account_change_never_displays_as_current` |
| 旧库兼容 | 旧策略原样保留、不自动获得整连接/网页授权、无新字段可读 | core `old_vaults_open_without_gaining_capabilities_or_losing_policies`、`legacy_e10_evidence_is_readable_through_the_contract` |

## 3. 稳定错误码与恢复动作

协议层错误码（`pman-protocol`）继续生效：`vault_locked`、`unknown_site`、
`site_inactive`、`harness_invalid`、`policy_denied`、`rate_limited`、
`pending_approval`、`response_blocked`、`request_failed`、`invalid_request`。

UI 层稳定目录（`api.ts::errorCodeInfo`，与 `status.rs::recovery_for` 对应）：

| 错误码 | 显示 | 恢复动作 |
| --- | --- | --- |
| `not_paired` | 客户端未配对 | 在 pman 桌面配对此 AI 客户端 |
| `harness_invalid` | 客户端已失效 | 重新配对客户端后再授权 |
| `policy_denied` | 授权不足 | 调整此客户端的授权范围 |
| `explicit_deny` | 已被明确拒绝 | 如需允许，先在 AI 工具中移除对应的拒绝规则 |
| `pending_approval` | 等待审批 | 在 pman 桌面批准该请求后重试 |
| `session_expired` | 会话已过期 | 重新登录或更新凭据 |
| `network_error` | 网络异常 | 检查网络连接后重试 |
| `timeout` | 请求超时 | 稍后重新检查 |
| `rate_limited` | 请求被限流 | 等待限流窗口结束后重试 |
| `service_paused` / `vault_locked` | AI 服务已暂停 / 服务未解锁 | 在 pman 桌面恢复 AI 服务 |
| `management_locked` | 管理界面已锁定 | 解锁管理界面；这不影响已授权的 AI 调用 |
| `account_context_changed` | 账号上下文已变化 | 重新确认账号与地址后重新检查或授权 |
| `forbidden` | 权限不足(403) | 确认服务端账号权限；403 不一定是凭据过期 |
| `response_blocked` | 响应疑似包含凭据，已阻止 | 重新登录后再试 |
| 未知码 | 状态未知 | 重新检查连接 |

所有错误与恢复文案为固定字符串，不含凭据、Cookie、token 或请求载荷。

## 4. 存储与迁移边界

- `connection_details.details_json` 结构不变；`extra` 内新增键（`identity_check`、
  `api_check`）带 serde 默认值，旧库缺省可读。
- 读取旧数据**不会**：启用 `ai_enabled`、把局部规则升级为整连接授权、
  生成任何网页能力、把已保存凭据标记为已验证。
- 写入证据不递增 generation（不打断在途已授权请求）；`update_details` 既有的
  账号变化撤销逻辑保持不变。
- 桌面 `list_sites` 响应新增 `dimensions` 字段；前端对缺失该字段的旧响应
  显示"尚未检查"（`dimensionSummary(undefined)`）。
- 状态版本未引入新 schema_version；后续若证据结构扩展，必须保持
  `CheckEvidence` 的 `#[serde(default)]` 全字段默认并在此文件登记。
