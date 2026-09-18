# BROWSER-CONTRACT（AI 网页操作通道）

版本：v1（对应 GLM-5.3-TODO T05）。实现：`rust/crates/pman-core/src/policy.rs`
（web 授权规则）、`rust/crates/pman-core/src/workspace.rs`（web_enabled）、
`rust/crates/pman-core/src/browser.rs`（动作授权与会话注册表）、
`desktop/src-tauri/src/browser_session.rs`（WebView2 会话执行器）、
`desktop/src-tauri/src/service.rs`（IPC 分发）、`desktop/src/ConnectionLibrary.tsx`
（开启入口与停止会话）。

## 0. 基本立场

- **网页能力是独立能力**。已有 API 授权不迁移、不暗示网页权限；API 规则
  `allow/deny` 不解释任何网页动作。
- **默认关闭**。连接必须显式开启 `web_enabled`，且必须存在针对客户端的
  web 授权规则；二者缺一，所有网页动作返回 `web_disabled`。
- 凭据隔离不变：AI 永远看不到 Cookie、token、密码；认证步骤由用户在
  隔离登录窗口完成。

## 1. 授权模型

| 层 | 字段 / 结构 | 默认 | 语义 |
| --- | --- | --- | --- |
| 连接层 | `ConnectionDetails.web_enabled: bool` | `false` | 该连接是否允许 AI 网页操作；false 时动作全部拒绝 |
| 客户端层 | 策略 `web` 数组：`{"site": alias, "actions": [...], "origins": [...]}` | 不存在 = 无网页权限 | 每客户端、每连接的动作白名单与 origin 范围 |

`actions` 枚举（v1）：`open`、`summary`、`click`、`fill`、`wait`、`close`。
`origins` 为允许的页面 origin 列表（如 `https://e10.example.test`）；
与连接 `site_url` 的 origin 不一致时动作拒绝（跨 origin 永不自动放行）。

**迁移与兼容**：旧策略 JSON 无 `web` 字段（serde default = 空）→ 无任何网页
权限；旧库 `connection_details` 无 `web_enabled`（default false）→ 关闭。
已保存、API 已授权的连接不会因升级获得网页能力。

撤销语义：移除策略中的 web 规则、关闭 `web_enabled`、撤销客户端或显式暂停
服务，都会 (a) 立即拒绝后续动作，(b) 关闭受影响会话（见 §4）。

## 2. 会话所有权与生命周期

- 会话由经过配对认证的客户端通过 IPC `browser_open` 创建，返回
  `session_id`（UUID）。`session_id` 绑定：客户端 id、harness、连接 alias、
  允许 origin、创建时的 generation 计数。
- **每个动作**重新校验：客户端身份（管道认证）、连接存在且 active、
  `ai_enabled`、`web_enabled`、web 授权规则覆盖该动作、动作 origin ∈
  授权 origins、session 未被撤销、generation 未变化。任一失败 → 拒绝并
  返回稳定错误码。
- 会话窗口是 pman 自己的 WebView2（应用数据目录），**不读取**用户外部
  浏览器的 Cookie 数据库，不注入用户日常浏览器。
- **登录/验证码**：远端页面要求认证时，由用户在既有隔离登录窗口人工完成；
  AI 侧动作只看到"需要登录"的脱敏摘要。管理界面锁定时禁止打开新的登录
  窗口；管理锁定本身不中断已授权的持续会话（与 API 语义一致）。

## 3. 动作协议（IPC，经既有配对与策略通道）

全部为已认证客户端的 IPC 操作，无匿名调试端口：

| 操作 | 参数 | 返回 | 副作用 |
| --- | --- | --- | --- |
| `browser_open` | `site`(alias_ref) | `session_id`、`origin`、`expires_at` | 打开隔离 WebView2 到连接 origin |
| `browser_summary` | `session_id` | 脱敏可交互摘要（见 §5） | 无 |
| `browser_click` | `session_id`、`selector`、`text?` | `{ok, page_url, changed}` | 点击元素 |
| `browser_fill` | `session_id`、`selector`、`value`、`secret?` | `{ok, page_url}`；`secret:true` 时值回显为 REDACTED | 填普通字段 |
| `browser_wait` | `session_id`、`selector?`、`text?`、`timeout_ms≤10000` | `{ok, page_url, found}` | 等待状态 |
| `browser_close` | `session_id` | `{ok}` | 关闭会话窗口 |

错误码（稳定）：`web_disabled`、`web_not_authorized`、`web_session_unknown`、
`web_origin_denied`、`web_action_unsupported`（文件上传/下载、支付/删除/发布
等敏感动作 v1 一律返回此码）、`web_response_blocked`（页面回显凭据）、
`harness_invalid`、`vault_locked`、`policy_denied`、`invalid_request`。

**不支持的动作（v1，明确列出）**：文件上传与下载、支付/转账、删除/发布等
不可逆提交（仅依据按钮文本不可靠判定，全部拒绝）、任意脚本执行
（`browser_eval` 不存在）、原始网络抓包、读取 localStorage/sessionStorage/
IndexedDB 的旁路、Cookie 读取或导出。

## 4. 执行边界

- **origin 限制**：WebView2 URL 与动作参数 origin 均须在授权列表内；导航到
  授权外 origin 时动作拒绝（页面内重定向离开授权 origin 后，后续动作拒绝
  并提示用户新增范围）。
- **远端页面不能调用宿主**：远程 origin 不启用 Tauri IPC/远程访问；宿主
  与页面之间唯一的通道是宿主发起的固定净化脚本（`ExecuteScript`），页面
  无法主动调用管理命令。
- **显式暂停 / 撤销 / 删除连接 / 客户端撤销**：服务层在每个动作前校验
  generation 与服务状态，命中即拒绝并关闭受影响会话窗口。管理锁定不停止
  已授权会话（与 API 一致），但禁止新建登录/认证窗口。
- **generation**：授权或连接元数据变化（`invalidate_requests`）后，旧会话
  全部失效。

## 5. 快照与响应脱敏

固定净化脚本在页面内执行，随后宿主做二次过滤：

- 输入字段值在以下情况返回 `***REDACTED***`：`type=password`；或
  `name/id/aria-label/placeholder` 命中敏感词（`password/passwd/pwd/
  passcode/otp/verification/token/secret/card/cvv/captcha`）；或字段带有
  `data-lpignore` 类密码管理器标记之外的 autocomplete=cc-*。**不仅依赖
  `type=password`**（合成站点测试覆盖 `type=text` 的敏感命名输入）。
- 不返回：Cookie、localStorage/sessionStorage、框架 URL 查询中的 token
  参数、`Set-Cookie`/`Authorization` 等头（快照根本不读网络层）。
- 摘要只包含：URL、标题、按钮/链接文本与选择器、表单字段的结构信息、
  非敏感输入的值、页面主文本的前若干行。
- 宿主侧把 vault 内该连接的全部凭据值（`http_proxy::secret_values`）作为
  阻断/替换表：任何动作响应若包含这些值 → `web_response_blocked`，
  不返回内容。
- 动作响应与审计都不含字段原值（`browser_fill(secret:true)` 只记录
  `REDACTED`）。

## 6. 活动与界面

- 每个动作写 `audit_log`（harness、site、动作名、结果码、脱敏 note），
  活动页可见；提供"停止网页会话"入口（连接详情与 AI 动作均可）。
- 详情页"网页操作"面板：开启开关（创建连接层能力 + 引导选择客户端授权）、
  显示账号/环境/允许 AI/允许站点、当前活动会话与停止按钮。仅在端到端
  通过后显示"可用"；未通过显示"尚未接入"（状态契约 web 维度联动：
  `web_enabled=false` → `not_available`；开启且未检查 → `unchecked`）。

## 7. 验收矩阵

| 场景 | 预期 | 自动化位置 |
| --- | --- | --- |
| API 授权升级到新版本 | 不获得网页能力 | core `web_capability_is_off_by_default_and_never_migrates` |
| web_enabled 但客户端无 web 规则（或反之） | `web_disabled` / `web_not_authorized` | core `browser_actions_fail_closed...` |
| 跨 origin 动作 / 授权外导航 | `web_origin_denied` | core `web_origin_outside_grant_is_denied` |
| 伪造 session_id / 撤销后旧会话 | `web_session_unknown` | core `web_sessions_fail_closed_after_revoke...` |
| 客户端撤销 / 连接暂停 / 服务暂停 | 立即拒绝（管道层既有语义） | desktop 既有 + `browser.rs` 校验 |
| 敏感字段快照（type=text 命名敏感） | REDACTED | 净化脚本单测（desktop，mask 规则函数） |
| 页面回显 vault 凭据值 | `web_response_blocked` | core `web_response_echoing_credentials_is_blocked` |
| 任意脚本/抓包/存储读取 | 动作不存在（协议层面无此操作） | 本契约 §4；desktop 无对应实现 |
| 真实网站登录后读表单、填非敏感字段、普通导航 | 人工验收（隔离 WebView2 运行时） | ACCEPTANCE.md 单列，不以模拟替代 |
