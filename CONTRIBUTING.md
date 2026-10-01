# 参与 pman 开发

pman 是 Windows 本地凭据与 AI 授权中心。优先改进真实流程的可靠性、错误恢复、安装和可验证性；保持现有协议、连接别名、迁移数据和授权边界兼容。

## 开始之前

- 阅读 [README](README.md)、[AGENTS.md](AGENTS.md)、[桌面说明](desktop/README.md) 和 [发布验收](desktop/RELEASE.md)。
- 基于清晰的问题提交小范围改动。新功能、大范围重写、许可证、权限模型和发布方式调整先与维护者讨论。
- 使用独立分支或副本，检查 `git status`，保留已有未提交改动。不要在当前用户的真实保险库上测试。

## 环境与检查

SDK 声明支持 Node 18+。使用自己明确选择的运行时，不自动替换本机 Node。桌面原生开发需要 Windows、Rust MSVC 工具链、C++ Build Tools / Windows SDK 和 WebView2。Python 兼容实现要求 Python 3.11+。

在仓库根目录执行：

```powershell
npm --prefix desktop ci
npm --prefix sdk/node test
npm --prefix desktop run test:build
npm --prefix desktop run test:ui
npm --prefix desktop run build
cargo test --manifest-path rust/Cargo.toml --workspace --locked

# Windows 原生层；先准备安装器使用的 CLI
npm --prefix desktop run build:native
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked
```

`build:native` 根据 Cargo 报告的实际产物路径准备 `desktop/src-tauri/bin/pm.exe`，支持自定义 `CARGO_TARGET_DIR`、Cargo 构建目录配置和目标架构目录。构建失败或产物缺失时直接失败，不取用旧 CLI。该命令不构建或发布安装器。

Python 兼容测试建议使用独立虚拟环境：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Linux / macOS 使用 `.venv/bin/python`。Python 测试创建临时数据目录和本机 HTTP 夹具；不需要实际账号。Rust 测试默认不会执行显式标记为 ignored 的发布二进制验收。

## 测试与凭据边界

- 只使用合成密码、Token、Cookie 和临时测试数据。不要读取或提交实际保险库、`.env`、配对材料、自动恢复材料、浏览器配置或客户端密钥。
- 手工原生验收必须使用可丢弃的 `PM_NATIVE_HOME`，避免操作实际 Vault 和 Codex / Claude 配置。AI 不执行真实解锁、配对、审批、授权或服务恢复。
- 修复缺陷时先给出复现方式，再补行为回归测试。不要降低 KDF、安全策略或脱敏要求来加快测试。
- 前端渲染测试与 `?preview=1` 只检查合成状态；Hello、锁屏、重启、真实 MCP 加载与安装仍按发布清单验收。

## 提交与问题报告

PR 说明应包含问题、改后行为、兼容性影响、已执行命令及结果、未验证项。界面改动附合成数据截图，并检查键盘、焦点、深浅主题与最小窗口。未执行的设备验收不能写成已通过。

普通问题可提交到仓库 Issues，附操作步骤、应用与系统版本、预期和实际结果。涉及潜在凭据泄漏的问题优先使用维护者启用的私密报告渠道；若没有可用渠道，公开内容仅描述症状和合成复现，不附真实凭据、Vault 或敏感日志。

自动化检查应覆盖 SDK、前端、Windows 原生层和 Python 兼容实现，并与发布、真实设备验收和安全审计分别记录。

## 持续集成

[CI 工作流](.github/workflows/ci.yml) 定义 JavaScript、Windows 原生层和 Python 兼容检查。Action 固定为核实的完整提交 SHA；Node 固定为 18.20.8 / 24.21.0，Rust 为 1.97.1，Python 为 3.11.9 / 3.14.4。最低 Node 版本用于检查已声明的兼容范围，本机运行时不由脚本替换。npm 使用 `ci`，Cargo 使用 `--locked`；Python 继续按项目现有依赖范围解析，暂不宣称完全锁定所有 Python 依赖。

工作流仅有 `contents: read` 权限，checkout 不保留凭据，没有密钥、发布或部署步骤。Windows 检查使用独立构建目录，覆盖原生 CLI 产物选择。远端存在该工作流后，main 更新、PR 或人工触发才可能运行；本地保存文件、YAML 校验和本机测试不代表 GitHub 在线检查通过。

运行时和 Action 更新应单独审查、核对官方版本并重跑相关检查。干净设备安装 / 卸载与 Windows 生命周期验收见 [发布清单](desktop/RELEASE.md)，在线 CI 也不能替代这些检查。
