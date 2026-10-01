# pman Windows 桌面工作台

Tauri 2 + React 17 + TypeScript，单一 Rust Broker 管理本机保险库、客户端、授权、登录和审计。原生 `pm.exe` 通过当前用户的命名管道连接桌面，不另起 Python daemon。

## 页面与工作流

- **凭据与连接**：48px 账号行，名称 / 账号 / 环境 / 状态 / AI 授权同屏；搜索、分组、收藏、右侧详情。支持密码、API Token、HTTP Basic、Cookie、WebView2 与 通用连接 登录。
- **AI 访问**：配对 → 场景路由 → 业务能力与参数约束 → 配置预览 / 写入 / 恢复 / 连通性检查。新客户端使用独立 harness，持续授权或自定义到期时间。场景只解析固定连接与账号；多条命中必须补充上下文。高级策略保留明确拒绝及旧版策略编辑。
- **活动**：按客户端、连接、结果筛选；展开响应统计和说明，可定位对应授权。
- **设置**：开机启动、闲置管理锁、Hello、深浅主题、减少动效、加密备份、迁移及旧版 HTTP 兼容入口。
- **全局审批**：顶栏始终显示待办；请求详情包含脱敏参数，批准绑定单次完整请求。AI 的登录协助与权限申请显示在同一队列；用户打开绑定连接的登录向导，或检查预填的具体范围后授权。

管理界面与 AI 服务状态独立。管理锁屏时不渲染凭据列表或秘密，仍显示服务状态及待审批数量。主动暂停持久化，恢复必须本人验证。数据刷新只更新列表，不重建编辑草稿；秘密只在人工点击后读取，失焦、锁定、切换页面或 30 秒后隐藏。

## 开发

在此目录执行：

```powershell
npm install
cargo build --manifest-path ..\rust\Cargo.toml -p pman-cli
npm run tauri dev
```

开发需要 Node、Rust MSVC 工具链、Visual Studio C++ Build Tools / Windows SDK 及 WebView2。安装后的桌面程序不要求开发工具或 Python。

```powershell
npm run build
node src/workbench.test.mjs
cargo check --manifest-path src-tauri\Cargo.toml
cargo test --manifest-path src-tauri\Cargo.toml
```

默认新数据目录 `%LOCALAPPDATA%\pman`。**不要在调试中读取用户的实际保险库、配对文件或自动恢复材料。** 自动化验收使用独立、可丢弃的 `PM_NATIVE_HOME` 合成目录；设置该变量也将客户端配置写入隔离目录，避免改动真实 Codex / Claude 配置。

### 只读浏览器预览

新版连接书架的流程、接口与能力边界见 [实现说明](../design/pman-next/IMPLEMENTATION.md)。预览可以切换页面和填写草稿，但不会保存凭据或执行授权。

```powershell
npm run dev
```

在 `http://127.0.0.1:1420/` 可选择合成数据预览。也可使用以下显式参数进行视觉验收：

| 参数                      | 画面                   |
| ------------------------- | ---------------------- |
| `?preview=1`              | 浅色连接书架，合成账号 |
| `?preview=1&theme=dark`   | 深色连接书架           |
| `?preview=1&state=locked` | 管理界面锁定、AI 运行  |
| `?preview=1&state=paused` | 主动暂停、等待本人恢复 |

真实 Tauri 进程忽略这些预览状态。浏览器没有原生接口时，所有持久化、生成、解密、授权、登录和配置操作明确报错，不模拟成功。

## 模块边界

| 模块                                | 责任                                          |
| ----------------------------------- | --------------------------------------------- |
| `src/api.ts`                        | IPC 类型、唯一 invoke 包装及显示层纯函数      |
| `src/App.tsx`                       | 身份门禁、独立服务状态、全局轮询 / 事件与审批 |
| `src/Credentials.tsx`               | 账号与连接、秘密临时显示、登录向导            |
| `src/Access.tsx`                    | 客户端、范围授权、配置及高级策略草稿          |
| `src/Activity.tsx` / `Settings.tsx` | 活动筛选、本机偏好、备份迁移                  |
| `src/ui.tsx` / `styles.css`         | 聚焦对话框、通用反馈及设计变量                |
| `src-tauri/src/service.rs`          | 单一 Vault / Broker 会话和后台任务            |
| `src-tauri/src/backend.rs`          | 本机管理命令和原生身份检查                    |
| `src-tauri/src/login.rs`            | 登录窗口、OAuth 事务与账号绑定                |
| `src-tauri/src/storage.rs`          | 备份 / 迁移 / 中断保护                        |

## 桌面 IPC 契约

这些命令只用于主窗口，并由原生层验证管理身份，不能暴露为 AI MCP 管理工具。

- 状态：`vault_status` 返回 `management_locked`、`service_running`、`service_paused`、`pending_approvals`、`hello_available`。
- 管理：`management_lock`、`management_unlock({password})`、`management_unlock_hello`；管理解锁保持原来的服务暂停选择。
- 服务：`service_pause`、`service_resume({password?,hello?})`、`window_hide`、`application_exit`。旧 `vault_lock` 是主动停用；旧 `vault_unlock` 是管理解锁。
- 凭据：保留 `site_add`、`site_update_metadata`、`site_rotate`、`site_remove`、`list_sites`；人工 `site_reveal`、`site_copy` 与 `generate_password` 不向 AI 开放。
- 配对：`client_pair`、`clients_list`、`client_revoke`，配置 `client_config_preview/apply/restore`、`client_test`。配对返回元数据和 ID，不返回秘密。
- 授权：`grant_add({harness,site,method,path,operation,capability?,constraints?,expiresAt?})`；连接详情的 `scenarios` 保存业务意图、能力 ID、服务匹配和附加条件；保留 harness 策略、一次性审批和审计命令。
- 协助：`assistance_list({status:'pending'})`、`assistance_decide({id,status:'handled'|'cancelled'})`。完成实际登录 / 授权后才标记 handled；标记状态本身不赋予权限。
- 登录：`open_login_window` / `login_capture_cookies` / `close_login_window`；通用连接 `authflow_begin` 后立即等待 `authflow_complete`，等待期间可 `authflow_cancel`；`authflow_check` 检查身份。
- 数据：`vault_backup`、`vault_import({password,sourcePath?})`、`vault_migrate_legacy({password,sourcePath?})`。省略路径时打开原生文件对话框。

前端监听 `management-locked`、`service-changed`、`approvals-changed`。管理锁定立即卸载工作台，并丢弃锁定之前发起的过时状态响应；2 秒状态轮询作为补充。4 秒元数据刷新保留编辑中的草稿。

## 验收边界

前端构建和只读浏览器预览只能验证界面、类型和交互。真实 Windows Hello、Windows 锁屏 / 睡眠 / 开机恢复、真实 通用连接 登录、MCP 客户端加载和干净设备安装需按照 [RELEASE.md](RELEASE.md) 单独完成。
