# Windows 构建与发布验收

这里列出发布门槛，**清单存在不代表已通过**。每次交付应记录实际执行的测试、产物和未验证项。

## 构建

在 `desktop` 目录执行：

```powershell
npm install
npm run build
node src/workbench.test.mjs
cargo test --manifest-path ..\rust\Cargo.toml --workspace
cargo test --manifest-path src-tauri\Cargo.toml
node --test ..\sdk\node\test\*.test.mjs
npm run tauri build -- --bundles nsis
```

`beforeBuildCommand` 使用 `npm run build:bundle`，构建前端并通过 `scripts/build-native.mjs` / `npm run build:native` 准备原生 CLI。安装目录必须同时包含桌面程序和 `pm.exe`，不能依赖 PATH 中的 Python `pm`。

NSIS 产物通常位于 `src-tauri\target\release\bundle\nsis\`；设置 `CARGO_TARGET_DIR` 时以实际构建输出为准。安装器按当前用户安装，WebView2 使用 bootstrapper。完全离线部署需预装 WebView2 或使用经验证的离线安装策略。

签名证书与时间戳配置属于发布环境，不提交私钥、证书密码或认证材料。开发产物如未签名应明确标注，不宣称生产发布完成。

## 合成数据自动验收

所有测试使用临时 Vault 和合成秘密，禁止使用实际保险库或真实用户凭据。

| 层次        | 场景                                                                        |
| ----------- | --------------------------------------------------------------------------- |
| 核心 / 协议 | Python v2 兼容、实际 KDF 参数、中文别名和 alias_ref                         |
| 授权        | 默认拒绝、持续 / 到期范围、明确拒绝优先、撤销立即阻断                       |
| 审批        | 完整请求绑定、参数变更不可复用、并发只能消费一次                            |
| 响应        | stdout / MCP / 错误 / 审计不泄漏合成秘密；敏感字段与回显脱敏                |
| 网络        | 跨 origin 重定向阻断、Cookie 域 / 路径 / Secure 属性、写入不自动重试        |
| 生命周期    | UI 锁不暂停服务；主动暂停持久化；管理解锁不取消暂停                         |
| 客户端配置  | 合并保留其他条目，错误格式不覆盖，恢复遇到后续改动不覆盖                    |
| 迁移        | 一致性快照、原文件保留、中断保留恢复副本、导入后重新配对                    |
| E10 / SDK   | state 校验、回调重放、取消、401 / 403 / 断网、固定 origin、无旧 Cookie 回退 |
| 前端        | 搜索 / 空状态、无原生接口的错误、对话框焦点 / Escape、深浅色和最小窗口      |

浏览器视觉预览使用显式 `?preview=1`，没有模拟原生操作成功。即使这些检查全部通过，仍需下面的真实设备验收。

## Windows 真实设备验收

使用独立 Windows 11 测试用户 / 测试机，在无 Python、Rust、旧 `pm` 的环境执行并记录：

1. 安装 NSIS；确认桌面与原生 CLI 均可使用。分别检查已安装 / 未安装 WebView2 的设备。
2. 创建保险库、保存密码、Token、Cookie、HTTP Basic；列表只读取元数据。人工查看失焦 / 30 秒隐藏；剪贴板 30 秒后仅在内容未变化时清除。
3. 配对 Codex / Claude，检查实际客户端工具加载和已授权请求。锁定管理界面后重复调用，确保继续成功。
4. Windows 锁屏、系统闲置、睡眠唤醒、关闭窗口分别验证；已授权调用只随系统睡眠暂停，唤醒后可恢复，管理界面保持锁定。
5. 重启并登录 Windows，服务自动恢复、管理界面仍锁定。随后主动暂停，再次重启，确认调用仍被阻断。
6. 主动暂停后仅解锁管理界面，确认没有恢复 AI 调用；再主动验证并恢复服务，确认原授权可用。
7. Windows Hello 成功、取消、不可用、验证期间锁屏及主密码回退；失败均不放开管理或服务。
8. 实际使用两个 E10 环境、两个账号验证绑定；登录取消、失效、403、网络中断正确区分。OAuth 不支持 state 的环境使用隔离 WebView2，不放宽校验。
9. E10 `e10-i18n --auth-check` 只验证连接。真实词条注册与 SQL 提交保留原 Skill 确认流程。
10. 导出备份，在另一测试目录恢复；原库保留，本机恢复材料不随备份迁移，原客户端不能直接使用恢复库。

## 交付记录模板

```text
源码版本 / 工作区差异：
构建命令及返回码：
安装包路径 / SHA-256 / 签名状态：
合成测试已执行：
Windows 设备与账号：
原生 MCP / CLI 验收：
Hello / 锁屏 / 重启 / 睡眠验收：
E10 环境与账号验收：
未完成项与限制：
```
