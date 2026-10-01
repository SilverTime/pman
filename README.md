# pman · 本地 AI 连接与授权中心

在 Windows 本机统一管理密码、Token、Cookie 和多环境账号。AI 通过已配对的原生 CLI / MCP 使用连接，认证由本机 Broker 注入，返回响应先脱敏。

**管理界面锁定不会暂停 AI。** 关闭窗口隐藏到托盘；Windows 锁屏和系统闲置仅锁定管理界面。主动暂停或锁定保险库才停止凭据调用，且重启后仍保持暂停，直到本人验证并恢复。

## 第一次使用

1. 打开 pman，创建本机保险库，或在界面中导入旧版保险库 / 加密备份。
2. 在“连接”点击“添加连接”，按连接方式选择浏览器登录、访问密钥、账号密码或授权登录。
3. 在同一流程选择可以使用此连接的 AI；尚未接入时，可直接配对 Codex、Claude Code 或通用客户端并配置 MCP。
4. 确认整连接授权，默认持续至撤销；系统检查所选客户端的本机配对和代理服务。自定义方法、路径与有效期在“AI 工具”中设置。
5. 在 AI 客户端重新加载配置，实际调用服务后检查结果。配置写入和本机代理检查均不代表真实业务操作已通过。普通密码仍仅供本人管理。

新凭据默认仅本人使用。配对客户端不会返回令牌；界面展示的客户端名称、身份标识和真实客户端 ID 都不是秘密。

## 常驻与锁定

| 行为                                   | 管理界面     | 已授权 AI 调用         |
| -------------------------------------- | ------------ | ---------------------- |
| 关闭窗口                               | 隐藏到托盘   | 继续                   |
| 锁定管理界面 / Windows 锁屏            | 需要重新验证 | 继续                   |
| 系统闲置，默认 15 分钟                 | 需要重新验证 | 继续                   |
| 睡眠 / 唤醒                            | 保持锁定     | 随系统暂停，唤醒后恢复 |
| 登录 Windows                           | 保持锁定     | 默认自动恢复           |
| 主动暂停 / 锁定保险库 / 退出并停止服务 | 锁定         | 停止，暂停状态持久化   |
| 撤销一项授权                           | 可继续管理   | 对应范围立即失效       |

管理验证支持主密码和可用的 Windows Hello。自动恢复材料由当前 Windows 用户的 DPAPI 保护，不保存主密码。它用于本机便利性，不构成同一 Windows 用户下恶意进程之间的强隔离。

## 原生 AI 接入

推荐通过桌面的接入向导生成配置，避免手工误填路径与 ID。原生 `pm.exe` 仅作为客户端桥接桌面进程，不直接读取凭据数据库。

```powershell
# 契约不需要解锁或访问秘密
pm.exe ai-help --json

# 以下 <paired-client-id> 使用桌面生成配置中的实际 client-... ID
pm.exe --client <paired-client-id> sites
pm.exe --client <paired-client-id> cred status gitlab
pm.exe --client <paired-client-id> resolve --intent jenkins.build --context service=xxx-service --context environment=test
pm.exe --client <paired-client-id> call --site gitlab --method GET --path /api/v4/projects
pm.exe --client <paired-client-id> status
```

也可通过非秘密环境变量 `PM_CLIENT` 指定已配对 ID。MCP 启动参数为 `mcp --client <paired-client-id>`，配置中不需要 `PM_TOKEN`。客户端名称或 harness 名称不能替代实际配对 ID。

### 结构化请求

`--stdin` 接收单个 JSON 对象，适合脚本和 SDK。不要将密码、Token、Cookie 放进请求体，凭据由原生服务注入。

```json
{
  "operation": "http",
  "request": {
    "site": "gitlab",
    "method": "GET",
    "path": "/api/v4/projects",
    "capability": "gitlab.projects.read",
    "query": { "per_page": "20" }
  }
}
```

MCP 提供 `pm_contract`、`pm_sites`、`pm_status`、`pm_resolve_scenario`、`pm_http`、`pm_connection_status` 和 `pm_approval_wait`。`pm_resolve_scenario` 使用人工配置的业务意图、服务、环境和附加条件解析唯一连接与能力 ID；零条或多条匹配都不会自动选择账号。`pm_request_login` / `pm_request_access` 将登录协助或权限申请放入桌面待办，`pm_request_status` 查询处理进度；这些操作不自行登录或授权。保留 `pman/2`、站点别名和 `alias_ref`。

范围外请求返回 `pending_approval` 和 `req_id`。用户可在桌面端选择“仅批准本次”，或把当前客户端、连接、方法和精确路径保存为“永久同意”（持续到手动撤销）。单次审批只消费一次，且绑定完整请求指纹；永久同意允许同一路径的参数或请求体变化，但不会扩展到其他方法、路径或连接。明确拒绝的范围始终优先。AI 不能解锁、批准、配对或恢复暂停服务。

场景授权可额外绑定 `capability`，并对 `query`、`form`、`json_body` 的顶层参数配置允许值或 glob。请求必须同时满足连接、方法、路径、能力 ID 和全部参数约束。未配置能力的旧授权继续兼容；配置了能力的授权不会接受未携带能力 ID 的调用。

### 通用连接 / Node SDK

连接使用完整 origin，并固定账号和环境。支持独立 WebView2 登录；OAuth 回调必须匹配一次性事务与 `state`，不支持时使用独立窗口。PKCE 仅在服务端支持已验证时启用。会话失效需重新登录，403 和网络错误分别呈现。

```js
import { createPmanClient } from "./sdk/node/index.mjs";

const client = createPmanClient({
  clientId: process.env.PMAN_CLIENT_ID,
  site: "office-api",
  expectedOrigin: "https://office.example.test",
});
const context = await client.getActiveContext(); // 非秘密元数据
const response = await client.request({
  method: "POST",
  path: "/api/secondev/cm/todo/tool/getModuleCodes",
  form: {},
});
```

`PMAN_EXECUTABLE`、`PMAN_CLIENT_ID`、`PMAN_SITE` 是非秘密配置。SDK 必须显式指定连接别名，不内置工作服务。认证流程、设备码、多步交换和旧连接转换参见 [通用认证配置](desktop/AUTHENTICATION.md)。

详见 [Node SDK](sdk/node/README.md)。

## 备份与旧版迁移

- 新桌面数据目录为 `%LOCALAPPDATA%\pman`；迁移通过人操作的文件选择窗口执行，AI 不读取该目录。
- 加密备份不包含 DPAPI 自动恢复材料和可使用的本机配对凭证；恢复后重新配对客户端。
- 旧版 SQLite 迁移保留原文件、ID、别名、密文、策略、令牌验证材料和审计，持久化实际 KDF 参数。迁移前关闭旧代理。
- 迁移用户可启用 `127.0.0.1:9777` 回环 HTTP 兼容入口，与原生入口共用一个 Broker；新安装默认关闭。兼容开关下次启动生效。
- Python 源码保留用于旧版兼容与回归；新 Windows 桌面和原生 CLI 不依赖 Python daemon。旧版人工管理命令不再是原生 CLI 的管理入口。

## 开发与验收

前端使用 React 17 / TypeScript，桌面使用 Tauri 2，凭据和策略核心使用 Rust。

```powershell
# 在 desktop 目录
npm ci
cargo build --manifest-path ..\rust\Cargo.toml -p pman-cli
npm run tauri dev

# 分层检查
npm run build
node src/workbench.test.mjs
npm run test:build
cargo test --manifest-path ..\rust\Cargo.toml --workspace --locked
cargo test --manifest-path src-tauri\Cargo.toml --locked
npm --prefix ..\sdk\node test
```

前端可用显式的只读合成预览：启动 `npm run dev` 后打开 `http://127.0.0.1:1420/?preview=1`。预览操作不会连接真实保险库，也不能据此认定原生权限、登录或 Windows 生命周期验收通过。

发布与设备验收见 [Windows 发布验收](desktop/RELEASE.md)，桌面命令边界见 [桌面开发说明](desktop/README.md)，新版交互与能力边界见 [连接书架实现说明](design/pman-next/IMPLEMENTATION.md)。

参与开发、合成测试与 PR 要求见 [贡献指南](CONTRIBUTING.md)。SDK 声明要求 Node 18+，开发命令不会自动更换本机运行时。分层检查不代表真实设备验收或安全审计完成。

[CI 定义](.github/workflows/ci.yml) 使用只读权限和固定版本，覆盖 SDK、构建脚本、前端、Windows 原生层和 Python 兼容实现；本地验证与 GitHub 在线运行分别记录，不自动发布。

## 目录

```text
desktop/src/             React 工作台、凭据、AI 访问、活动、设置与 IPC 类型
desktop/src-tauri/src/   管理认证、常驻生命周期、登录、配置和迁移
rust/crates/pman-core/   Vault、Broker、策略、DPAPI/命名管道、通用认证引擎
rust/crates/pman-cli/    原生 CLI / stdio MCP 桥接
rust/crates/pman-protocol/  pman/2 协议类型
sdk/node/               无秘密的 Node 请求适配层
src/pman/               保留的 Python 兼容实现
```
