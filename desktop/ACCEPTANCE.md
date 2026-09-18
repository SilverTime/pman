# pman 0.4.0 本地交付与验收记录

日期：2026-09-15。范围：Windows 个人本机凭据与 AI 授权工作台。

## 已实现

- 单一 Rust Broker、当前用户命名管道、原生 `pm.exe` CLI / stdio MCP。桌面运行不依赖 Python daemon。
- 管理界面锁定与 AI 服务暂停独立。关窗驻留托盘；界面闲置、锁屏及系统会话事件只锁管理界面。DPAPI 支持登录后恢复；主动暂停持久化，管理解锁不会恢复 AI。
- 原生管理认证、Windows Hello 接口、自动启动注册、单实例、剪贴板定时清理、托盘审批通知。
- 深浅色工作台、密码 / Token / Cookie / HTTP Basic、账号环境固定绑定、配对与范围授权、单次审批、撤销、活动与人工处理请求。
- E10 OAuth / 隔离 WebView2、state 校验、身份检查、Cookie 属性、Node 适配层，以及 `.agents` 下 `e10-i18n` 的认证和请求迁移。
- 全量加密备份、旧库只读迁移、失败回滚、恢复后重新配对。中断请求保留结果未知记录，不自动重试。

## 构建产物

安装包：`src-tauri/target/release/bundle/nsis/pman Vault_0.4.0_x64-setup.exe`。

原生程序：`src-tauri/target/release/pman-desktop.exe`；CLI：`../rust/target/release/pm.exe`。

NSIS 以当前用户安装，安装清单包括同目录的桌面程序与 `pm.exe`。WebView2 使用官方 bootstrapper；本地构建未签名。没有将实际保险库、配对材料或恢复密钥打进安装包。

安装包 SHA-256：`F67B838CB542936E382F8A38218EDADF8B6B85A320FFD302F054DF1354C1CDD2`。

构建和发布 EXE 验收主机：Windows 11，系统版本 `10.0.26200.0`。最终 NSIS 构建返回码为 0，最终发布 EXE 的隔离验收再次通过。

## 已执行的自动化验证

| 层次 | 结果 | 证据范围 |
| --- | --- | --- |
| Rust 核心 / 协议 / CLI | 48 + 5 + 3 项通过 | DPAPI、实际命名管道与大响应、伪造身份、撤销及到期、审批并发单次消费、脱敏、重定向、E10、多环境绑定、备份恢复、请求中断审计 |
| 桌面 Rust | 20 项通过 | 管理锁不影响真实本地 HTTP 调用、闲置、重启恢复与持久暂停、管理认证 epoch、配置保留和重复写入、单实例、迁移失败回滚 |
| 实际发布程序 | 1 项通过 | 将桌面 EXE 与原生 CLI 复制进临时目录，以合成保险库及仅包含 Windows System32 的 PATH 启动，验证 CLI / MCP 初始化、工具列表、HTTP 调用、回显脱敏、主动暂停后的重启 |
| 前端 | 7 项通过 | 原生边界、锁定与暂停视图、状态区分、预览不可进入真实服务、两套主题的指定文字对比度 |
| E10 SDK / 已安装 I18n 脚本 | 10 项通过 | Node 24.19.0；固定 origin、审批、无旧认证回退；实际脚本经合成响应完成检查、翻译、SQL 导出、模拟提交及临时源码替换 |
| 旧 Python 协议回归 | 74 项通过 | 旧 CLI、daemon、MCP、保险库、策略及安全回归；仅用于兼容验证，不是新版运行依赖 |

合计 **168 项自动化验证**。浏览器另完成合成数据交互检查：搜索、空状态、新增、对话框焦点与 Escape、深浅主题、最小窗口、审批和授权范围预填。浏览器预览不模拟原生操作成功。

核心与桌面测试使用临时合成保险库；测试过程没有读取实际密码或 Cookie，没有执行真实注册词条、SQL 提交、Windows Hello 验证或真实账号登录。

## 尚未完成的真实设备验收

以下不能由合成测试或受限 PATH 的测试替代，当前不标记为通过：

- 全新 Windows 11、未装开发工具与 WebView2 的安装流程，以及实际 Codex / Claude 客户端加载 MCP。
- Windows Hello 的真人成功 / 取消、真实锁屏、睡眠唤醒、Windows 重启登录及自动启动注册。
- 真实 E10 多环境 / 多账号登录与 `e10-i18n --auth-check`。

项目 `AGENTS.md` 将保险库初始化、解锁、令牌与授权管理列为人类操作。真实验收应由用户在工作台创建或迁移保险库、完成登录与配对后继续；自动化测试只操作合成数据。

### 继续真实 E10 验收

1. 安装后，在工作台连接 `https://www.e-cology.com.cn`，使用固定别名，例如 `e10-i18n`，完成本人登录。
2. 将连接开放给 AI，配对客户端并核对 I18n 接口范围。客户端 ID 使用界面生成的 `client-…`，不使用显示名替代。
3. 为运行 Skill 的终端设置非秘密变量 `PMAN_CLIENT_ID` 和 `PMAN_E10_SITE`。自定义安装目录另设置 `PMAN_EXECUTABLE` 为原生 `pm.exe` 的绝对路径。
4. 执行 `node C:/Users/bvzgo/.agents/skills/e10-i18n/scripts/e10-i18n.mjs --auth-check`。真实注册与 SQL 提交仍按原 Skill 流程确认。

默认安装位置下，SDK 使用 `%LOCALAPPDATA%\pman Vault\pm.exe`，不会从 PATH 静默调用旧 Python `pm`。

## 复现发布程序验收

在仓库根目录执行；仅使用工具生成的合成数据：

```powershell
$env:PM_KDF_ITERATIONS = '1000'
$env:PM_ACCEPTANCE_DESKTOP = Join-Path $PWD 'desktop/src-tauri/target/release/pman-desktop.exe'
$env:PM_ACCEPTANCE_CLI = Join-Path $PWD 'rust/target/release/pm.exe'
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked --offline installation_tests::installed_binaries_work_without_python_rust_or_legacy_pm -- --ignored --test-threads=1
Remove-Item Env:PM_KDF_ITERATIONS, Env:PM_ACCEPTANCE_DESKTOP, Env:PM_ACCEPTANCE_CLI
```

`PM_KDF_ITERATIONS=1000` 只用于上述可丢弃的测试保险库，不用于实际保险库。
