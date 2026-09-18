# 0.4.1：审批通知导致桌面崩溃

## 现象与根因

Windows 在 2026-09-15 21:04 记录 `pman-desktop.exe 0.4.0` 的 `APPCRASH`，异常码 `0xc0000374`（堆内存损坏）。有待审批请求时启动通知流程，因此重新打开也会再次触发。

通知注册的 `PROPVARIANT` 使用 `VT_LPWSTR`，但其指针借用了 Rust `Vec<u16>` 的内存。Windows crate 为 `PROPVARIANT` 实现的 `Drop` 会调用 `PropVariantClear`；它会释放这段借用内存，随后 Rust 容器再次释放，导致堆损坏。代码中“不调用 PropVariantClear”的注释未考虑自动析构。

## 修复

使用 `SHStrDupW` 创建 Windows COM 所有的字符串，将它的所有权交给 `PROPVARIANT`。Rust 输入缓冲区与 Windows 属性值分别拥有自己的内存。

不改变保险库、配对身份、已有授权或待审批记录。桌面版本升级为 0.4.1，原生 CLI 协议不变。

## 验证

新增真实 Windows COM 回归测试：256 次创建 ShellLink 属性存储、设置应用身份、释放原属性值、重新读取身份并释放全部对象。无需实际密码、保险库、桌面通知或开始菜单文件。

此前隔离验收通过 `PM_NATIVE_HOME` 跳过通知注册，未覆盖本次故障路径。原 0.4.0 自动化记录不能作为通知可用性的证明。

修复验证：桌面单元测试 21 项通过；新 release 程序在最小 PATH 下的安装后二进制验收通过；NSIS 0.4.1 打包成功。本机已备份并替换桌面 EXE，重新启动后原 Codex 配对可查询服务，管理界面锁定而服务继续运行，原待审批请求仍为 pending。无需重新配置凭据。
