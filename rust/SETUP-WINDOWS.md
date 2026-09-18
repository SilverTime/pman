# Windows 构建环境

当前工作区按 `x86_64-pc-windows-msvc` 构建。推荐安装 Rustup + MSVC，不要装 GNU
工具链来替代，因为 Tauri/Windows 原生依赖需要 MSVC linker 和 Windows SDK。

## 需要安装的内容

1. Rustup 安装器：
   `https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe`
2. Visual Studio Build Tools，选择 **Desktop development with C++**，至少包含：
   - MSVC x64/x86 build tools
   - Windows 10/11 SDK
3. Node.js LTS + npm（Tauri 前端构建需要）。
4. Windows 10/11 的 WebView2 Runtime（桌面端运行时）。

## 下载与安装目录

安装器可以先下载到任意临时目录，例如：

```text
C:\Users\<当前用户名>\Downloads\rustup-init.exe
```

运行后 Rustup 默认安装到：

```text
C:\Users\<当前用户名>\.cargo\bin\   # cargo、rustc、rustfmt
C:\Users\<当前用户名>\.rustup\       # toolchain 与 target
```

不要把 Rust toolchain 放进本项目；项目只需要 `rust/target/` 作为构建产物目录。

## 安装命令

在新的 PowerShell 窗口执行：

```powershell
& "$env:USERPROFILE\Downloads\rustup-init.exe" -y `
  --default-toolchain stable-x86_64-pc-windows-msvc `
  --profile minimal

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
rustc -Vv
cargo -V
```

## 项目验证

```powershell
Set-Location E:\Code\ToolsGO\local-password\rust
cargo test --workspace
cargo run -p pman-cli -- protocol
```

预期输出包含：

```json
{
  "protocol": "pman",
  "protocol_version": 2,
  "ok": true,
  "error_code": "ok"
}
```

如果 `cargo test` 报 `link.exe` 或 Windows SDK 缺失，回到 Build Tools Installer，补选
上述 C++ workload 和 SDK 后重新打开 PowerShell。
