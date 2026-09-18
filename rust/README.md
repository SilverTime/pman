# pman Rust workspace

这是桌面端 D1 的 Rust 基础工程，先固定跨实现协议，再逐步替换 Python broker。

## 当前 crate

- `pman-protocol`：`pman/2` 请求、响应和稳定错误码；与 Python
  [pman-protocol.md](../pman-protocol.md) 对齐。
- `pman-core`：核心边界的最小实现，目前提供请求校验和结果构造；后续加入
  vault、policy、broker、audit、approval。
- `pman-cli`：Rust CLI smoke 入口，供后续 MCP/daemon/桌面端共用。

在安装 Rust MSVC 工具链后运行：

```powershell
cargo test --workspace
cargo run -p pman-cli -- protocol
```

Windows 安装清单见 [SETUP-WINDOWS.md](SETUP-WINDOWS.md)。

## GitLab Cookie 写入认证

`login` / `cookie_jar` 连接带有有效 `_gitlab_session` 时，原生 broker 对
`/api/v4/` 下的 POST、PUT、PATCH、DELETE 请求自动准备 CSRF 认证。
它先访问同源、相同 GitLab 路径前缀下的 `/-/profile`，从 HTML meta 标签获取
CSRF token，仅在内存中将其注入本次请求的 `X-CSRF-Token`。这属于已授权
写入请求的认证准备，不会增加调用方的业务权限，也不会向调用方返回页面内容。

- 不跟随重定向，不扩大 Cookie 的域、路径或 Secure 范围。
- 页面不可用、非 HTML、超出大小限制或 token 无效时，停止发送业务写入。
- 不缓存或落盘 token；服务端回显 token 时阻止返回；不自动重试业务写入。
- GET、非 GitLab Cookie 和 API token / E10 认证沿用原逻辑。
- 现有授权规则无需重新添加；已安装桌面 broker 必须更新并重启后才会生效。

针对性回归：`cargo test -p pman-core http_proxy::tests`（在 `rust` 目录运行）。

当前不在 Rust 层复制 Python 的密文格式；Vault 兼容读取会在下一步加入迁移测试。
