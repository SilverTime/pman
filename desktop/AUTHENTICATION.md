# 通用认证配置

添加连接以连接方式组织：浏览器登录、访问密钥、HTTP Basic 账号密码、授权登录。
个人密码只用于保管。服务地址、登录端点、身份字段和额外请求参数属于用户配置；产品不需要企业专用认证类型。

## 普通用户

- 浏览器登录：输入名称和地址，在独立窗口登录，再保存会话。
- 访问密钥：输入 Token；请求头默认为 Authorization，可自定义。
- 账号密码：HTTP Basic；普通网页表单请使用浏览器登录。
- 授权登录：选择授权码 + PKCE 或设备码，填写 Client ID、授权路径、令牌路径及身份接口。授权服务器与业务 API 不同域时，显式填写授权服务器地址。
- 复杂流程：展开“高级认证配置”，粘贴完整 JSON；它替换默认授权表单生成的配置。

## 配置结构

`authorization`：`path`、可选 `origin`、`kind`（code/device）、`params`、`callback_port`（0 自动端口）、`pkce`（默认 true）。回调路径固定 `/callback`，state 始终严格校验。

`exchange` / `refresh`：最多各 8 个 HTTP 步骤，每步包括：

- `path`：相对于服务器的路径，禁止绝对 URL、跳转地址、查询字符串和目录穿越；查询参数使用 `query`。
- `method`：GET（默认）或 POST；`query`、`form`、`json`、`headers` 配置请求内容。form 与 json 不能同时使用。
- `extract`：变量名 → 候选来源数组，依次尝试，第一个非空值胜出；找不到会失败。
- `optional_extract`：相同格式，找不到则保留原值。
- 来源：JSON Pointer（如 `/data/token`）、`header:X-Session`、`cookie:SESSION`。
- `cookie_header`：响应 JSON 中完整 Cookie 字符串的 JSON Pointer。该显式映射产生当前目标域、根路径的 Cookie；Set-Cookie 则保留服务端的路径、有效期和 HTTPS 限制。
- `skip_if_present`：这些变量全部已有值时跳过该步骤。
- `expect`：JSON Pointer → 必须相等的 JSON 值，用于识别业务失败。

`headers` / `cookies`：业务请求认证映射。Cookie 来源按每次请求的域名、路径、HTTPS 和有效期过滤；请求不跟随重定向。

`check`：`request` 配置身份接口请求；`user_id` 必填，`user_name`、`tenant_id`、`tenant_name` 可选，均使用候选来源数组。只有身份检查成功才报告验证通过；账号和组织改变会拒绝保存。检查接口必须由配置者确认是只读操作；部分系统的只读身份接口使用 POST，因此支持 GET/POST。

## 变量

- `${code}`：授权码，设备码流程中为 device_code。
- `${redirect_uri}`、`${verifier}`：本次回调地址与 PKCE verifier。
- `${origin}`：当前请求 origin。
- `${var:name}`：前序步骤提取的受保护变量。
- `${cookie:NAME}`：符合当前请求作用域的 Cookie 值。
- `${secret:token}`：现有访问密钥；同样可引用本地 secret 的其他顶层字符串字段。

没有脚本执行、动态 URL 或外部命令。变量仅在本机原生进程解析，不返回 AI。固定请求头中也可能包含秘密，因此配置被加密保存且不自动回显。

## 浏览器会话映射示例

```json
{
  "headers": {"X-Session": "${cookie:SESSION}", "X-Client": "desktop"},
  "check": {
    "request": {"path": "/api/identity", "expect": {"/ok": true}},
    "user_id": ["/data/id"],
    "tenant_id": ["/data/organization"],
    "user_name": ["/data/name"]
  }
}
```

## 多步交换示例

```json
{
  "authorization": {"path": "/authorize", "params": {"client_id": "your-app-id"}, "pkce": true},
  "exchange": [
    {"path": "/token", "method": "POST", "form": {"grant_type": "authorization_code", "client_id": "your-app-id", "code": "${code}", "redirect_uri": "${redirect_uri}", "code_verifier": "${verifier}"}, "extract": {"access": ["/data/token"]}, "optional_extract": {"refresh": ["/data/refresh_token"]}},
    {"path": "/session", "method": "POST", "query": {"access_token": "${var:access}"}, "cookie_header": "/data/cookies"}
  ],
  "headers": {"X-Session": "${cookie:SESSION}"},
  "check": {"request": {"path": "/identity"}, "user_id": ["/id"], "tenant_id": ["/organization"]},
  "refresh": [
    {"path": "/renew", "method": "POST", "form": {"refresh_token": "${var:refresh}"}, "cookie_header": "/cookies", "optional_extract": {"refresh": ["/refresh_token"]}}
  ]
}
```

这些是合成协议示例，不绑定任何工作服务。真实接口路径、字段、权限与 PKCE 支持必须根据目标系统配置。

## 旧连接与验证

在连接详情选择“认证配置”，指定通用连接方式及完整新配置。原有凭据、账号绑定和授权保留，旧检查证据清除。不会自动猜测旧服务的认证参数，也不会读出凭据供用户或 AI 转换。转换后先检查连接；需要时重新登录。

刷新通过连接详情“刷新凭据”手动执行；失败不覆盖原有凭据。未配置 refresh 的连接使用重新登录。

本地模拟服务覆盖：授权回调 state/PKCE、设备码 pending 轮询、多步交换、JSON/Header/Cookie 提取、作用域限制、身份与组织绑定、401/403、刷新失败保留数据和旧连接配置转换。真实服务登录与已安装客户端验收应单独完成。

## 2026-09-20 本地验证记录

- Rust 核心：106 项通过，包含通用认证的真实本地 HTTP 请求链路、设备码轮询、回调攻击拒绝和旧连接转换。
- Tauri 原生模块：28 项通过；安装包验收 1 项按原要求跳过，未提供独立发布程序路径。
- UI：20 项通过，TypeScript 检查和 Vite 前端构建通过。
- Node SDK 测试通过；新增缺少连接别名时拒绝调用的验证。
- 浏览器使用合成数据预览，确认四种入口、授权方式表单与高级配置展示。不是实账号登录验收。
- 最终核心/原生合成测试将 `PM_KDF_ITERATIONS=1000` 仅设置在测试子进程中；不修改产品加密默认值，也不接触实际保险库。
- 未更新已安装程序、未提交或推送 Git。真实工作服务需由已配对客户端按用户配置完成验收。
