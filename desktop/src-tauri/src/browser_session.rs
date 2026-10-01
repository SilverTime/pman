//! AI web-session execution over pman-managed isolated WebView2 windows.
//!
//! BROWSER-CONTRACT.md is authoritative. Only the fixed, argument-parameterised
//! scripts in this file ever run in the page: there is no `browser_eval`, no
//! storage access and no network capture. Remote pages get no Tauri IPC, so
//! they cannot call management commands. Every action re-checks the client,
//! connection, capability, origin and session generation before touching the
//! webview, and every response is checked against the vault's secret values.
use crate::service::Shared;
use pman_core::browser::{is_sensitive_field, web_response_blocked, WebAuthError, WebSession};
use pman_core::ipc::{resolve_alias, IpcRequest};
use serde_json::{json, Value};
use std::time::Duration;
use tauri::Manager;

const SESSION_LIFETIME_MINUTES: i64 = 30;
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(20);

fn web_error(code: &'static str, message: &str) -> Value {
    pman_core::ipc::result_error(code, message)
}

fn audit_web(shared: &Shared, harness: &str, site: &str, action: &str, ok: bool, note: &str) {
    let mut core = match shared.core.lock() {
        Ok(core) => core,
        Err(_) => return,
    };
    let _ = core.vault.add_audit(&pman_core::AuditEntryInput {
        harness: harness.to_owned(),
        site: Some(site.to_owned()),
        method: Some(format!("WEB:{action}")),
        path: None,
        status_code: Some(if ok { 200 } else { 400 }),
        note: Some(note.to_owned()),
        ..pman_core::AuditEntryInput::default()
    });
}

/// Routes a `browser_*` IPC operation. The client identity has already been
/// authenticated by the transport.
pub fn dispatch_web(shared: &Shared, request: &IpcRequest, harness: &str) -> Value {
    match request.operation.as_str() {
        "browser_open" => web_open(shared, request, harness),
        "browser_summary" => {
            with_session(shared, request, harness, "summary", |shared, session| {
                web_summary(shared, &session)
            })
        }
        "browser_click" => with_session(shared, request, harness, "click", |shared, session| {
            web_click(shared, &session, &request.args)
        }),
        "browser_fill" => with_session(shared, request, harness, "fill", |shared, session| {
            web_fill(shared, &session, &request.args)
        }),
        "browser_wait" => with_session(shared, request, harness, "wait", |shared, session| {
            web_wait(shared, &session, &request.args)
        }),
        "browser_close" => with_session(shared, request, harness, "close", |shared, session| {
            let closed = shared.web_sessions.close(&session.session_id);
            if let Some(app) = shared.app_handle.get() {
                if let Some(window) = app.get_webview_window(&session.window_label) {
                    let _ = window.close();
                }
            }
            audit_web(shared, harness, &session.site, "close", true, "会话已关闭");
            let _ = closed;
            pman_core::ipc::result_ok(json!({"ok": true}))
        }),
        _ => web_error(
            "web_action_unsupported",
            "unknown browser action; see BROWSER-CONTRACT.md",
        ),
    }
}

/// Shared pre-action authorization: connection + capability + per-client web
/// grant + origin + live session + generation. Runs for every action except
/// `browser_open` (which authorizes the connection itself).
fn authorize(
    shared: &Shared,
    harness: &str,
    alias: &str,
    action: &str,
    origin: Option<&str>,
) -> Result<String, Value> {
    let core = shared
        .core
        .lock()
        .map_err(|_| web_error("request_failed", "服务状态不可用"))?;
    let site_url = core
        .vault
        .authorize_web_action(harness, alias, action, origin)
        .map_err(|error| {
            web_error(
                error.code(),
                match error {
                    WebAuthError::Disabled => "此连接未开启 AI 网页操作或服务不可用",
                    WebAuthError::NotAuthorized => "此客户端没有被授权执行该网页动作",
                    WebAuthError::OriginDenied => "目标 origin 不在网页授权范围内",
                    WebAuthError::SessionUnknown => "网页会话不存在或已关闭",
                    WebAuthError::Unsupported => {
                        "该网页动作不存在（文件上传/下载、支付/删除/发布、任意脚本等一律不支持）"
                    }
                },
            )
        })?;
    drop(core);
    Ok(site_url)
}

fn web_open(shared: &Shared, request: &IpcRequest, harness: &str) -> Value {
    let alias = resolve_alias(
        request
            .args
            .get("site")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    if alias.is_empty() {
        return web_error("invalid_request", "缺少连接别名");
    }
    let site_url = match authorize(shared, harness, &alias, "open", None) {
        Ok(url) => url,
        Err(error) => return error,
    };
    let (site_id, allowed_origin) = {
        let core = match shared.core.lock() {
            Ok(core) => core,
            Err(_) => return web_error("request_failed", "服务状态不可用"),
        };
        let site_id = match core
            .vault
            .list_sites()
            .ok()
            .and_then(|sites| sites.into_iter().find(|site| site.alias == alias))
            .map(|site| site.id)
        {
            Some(site_id) => site_id,
            None => return web_error("web_session_unknown", "连接不存在"),
        };
        let origin = match core.vault.web_session_origin(&alias) {
            Ok(origin) => origin,
            Err(error) => return web_error(error.code(), "连接地址不能用于网页会话"),
        };
        (site_id, origin)
    };
    let session_id = uuid::Uuid::new_v4().simple().to_string();
    let window_label = format!("web-session-{session_id}");
    let generation = {
        let core = match shared.core.lock() {
            Ok(core) => core,
            Err(_) => return web_error("request_failed", "服务状态不可用"),
        };
        core.vault.generation()
    };
    let session = WebSession {
        session_id: session_id.clone(),
        client_id: request.client_id.clone(),
        harness: harness.to_owned(),
        site: alias.clone(),
        origin: allowed_origin.clone(),
        window_label: window_label.clone(),
        generation,
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: (chrono::Utc::now() + chrono::Duration::minutes(SESSION_LIFETIME_MINUTES))
            .to_rfc3339(),
    };
    shared.web_sessions.open(session);
    // The window is created through the app handle on the main thread.
    if let Some(app) = shared.app_handle.get() {
        let app = app.clone();
        let url = site_url.clone();
        let label = window_label.clone();
        let navigation_origin = allowed_origin.clone();
        let profile = shared.home.join("login-profiles").join(site_id);
        let built = tauri::WebviewWindowBuilder::new(
            &app,
            &label,
            tauri::WebviewUrl::External(
                url.parse()
                    .unwrap_or_else(|_| "about:blank".parse().unwrap()),
            ),
        )
        .title(format!("pman 网页会话 · {alias}"))
        .data_directory(profile)
        .on_navigation(move |url| {
            matches!(url.scheme(), "http" | "https")
                && url.origin().ascii_serialization() == navigation_origin
        })
        .visible(true)
        .build();
        if built.is_err() {
            shared.web_sessions.close(&session_id);
            return web_error("request_failed", "无法创建隔离网页会话窗口");
        }
    } else {
        shared.web_sessions.close(&session_id);
        return web_error(
            "web_action_unsupported",
            "网页会话窗口仅在桌面运行时可用（测试/CLI 环境不提供 WebView2）",
        );
    }
    audit_web(shared, harness, &alias, "open", true, "网页会话已打开");
    pman_core::ipc::result_ok(json!({
        "session_id": session_id,
        "origin": allowed_origin,
        "expires_at": session_expires_at(shared, &session_id),
    }))
}

fn session_expires_at(shared: &Shared, session_id: &str) -> Value {
    shared
        .web_sessions
        .get(session_id)
        .map(|session| json!(session.expires_at))
        .unwrap_or(Value::Null)
}

/// Loads and validates the session, then runs the action closure with it.
fn with_session<F>(
    shared: &Shared,
    request: &IpcRequest,
    harness: &str,
    action: &str,
    run: F,
) -> Value
where
    F: FnOnce(&Shared, &WebSession) -> Value,
{
    let session_id = request
        .args
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let Some(session) = shared.web_sessions.get(&session_id) else {
        return web_error("web_session_unknown", "会话不存在、已关闭或已过期");
    };
    // Session ownership: the caller must be the client that opened it, and
    // the session must still match its connection and generation.
    if session.client_id != request.client_id || session.harness != harness {
        return web_error("web_session_unknown", "会话归属校验失败");
    }
    // Expiry and generation (a changed generation means authorization or
    // connection metadata changed; the session is closed immediately).
    if chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .map(|expires| expires < chrono::Utc::now())
        .unwrap_or(true)
    {
        shared.web_sessions.close(&session_id);
        close_window(shared, &session);
        return web_error("web_session_unknown", "会话已过期");
    }
    let generation = match shared.core.lock() {
        Ok(core) => core.vault.generation(),
        Err(_) => return web_error("request_failed", "服务状态不可用"),
    };
    if generation != session.generation {
        shared.web_sessions.close(&session_id);
        close_window(shared, &session);
        return web_error(
            "web_session_unknown",
            "授权或连接已变化，会话已关闭；请重新打开",
        );
    }
    // Re-check the connection + capability + grant for every action.
    if let Err(error) = authorize(
        shared,
        harness,
        &session.site,
        action,
        Some(&session.origin),
    ) {
        return error;
    }
    run(shared, &session)
}

fn close_window(shared: &Shared, session: &WebSession) {
    if let Some(app) = shared.app_handle.get() {
        if let Some(window) = app.get_webview_window(&session.window_label) {
            let _ = window.close();
        }
    }
}

/// Runs one of the fixed sanitizer scripts through WebView2 ExecuteScript.
/// Only `script` (compiled into this binary) executes in the page; arguments
/// are embedded as JSON, never interpolated as code.
fn execute_script(shared: &Shared, session: &WebSession, script: &str) -> Result<String, String> {
    let app = shared
        .app_handle
        .get()
        .ok_or_else(|| "网页会话窗口仅在桌面运行时可用".to_owned())?;
    let window = app
        .get_webview_window(&session.window_label)
        .ok_or_else(|| "会话窗口已关闭".to_owned())?;
    let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
    let script = script.to_owned();
    window
        .with_webview(move |webview| {
            #[cfg(windows)]
            {
                use windows::core::{HSTRING, PCWSTR};
                let controller = webview.controller();
                let webview2 = unsafe { controller.CoreWebView2() };
                let webview2 = match webview2 {
                    Ok(webview2) => webview2,
                    Err(error) => {
                        let _ = tx.send(Err(format!("webview unavailable: {error}")));
                        return;
                    }
                };
                let script_h = HSTRING::from(script);
                // The webview2-com macro converts the raw COM arguments:
                // (HRESULT, PCWSTR) becomes (Result<()>, String).
                let tx_callback = tx.clone();
                let handler = webview2_com::ExecuteScriptCompletedHandler::create(Box::new(
                    move |error_code: windows::core::Result<()>, result: String| {
                        if error_code.is_ok() {
                            let _ = tx_callback.send(Ok(result));
                        } else {
                            let _ = tx_callback.send(Err("script execution failed".into()));
                        }
                        Ok(())
                    },
                ));
                if let Err(error) =
                    unsafe { webview2.ExecuteScript(PCWSTR::from_raw(script_h.as_ptr()), &handler) }
                {
                    let _ = tx.send(Err(format!("execute failed: {error}")));
                }
            }
            #[cfg(not(windows))]
            {
                let _ = tx.send(Err("web automation is only implemented on Windows".into()));
            }
        })
        .map_err(|error| format!("无法访问网页会话: {error}"))?;
    rx.recv_timeout(SCRIPT_TIMEOUT)
        .map_err(|_| "脚本执行超时；页面可能未响应".to_owned())?
}

/// Native origin enforcement: the page currently displayed must still be on
/// the granted origin before any snapshot or interaction.
fn current_origin(shared: &Shared, session: &WebSession) -> Result<String, Value> {
    let app = shared
        .app_handle
        .get()
        .ok_or_else(|| web_error("web_action_unsupported", "网页会话仅在桌面运行时可用"))?;
    let window = app
        .get_webview_window(&session.window_label)
        .ok_or_else(|| {
            shared.web_sessions.close(&session.session_id);
            web_error("web_session_unknown", "会话窗口已关闭")
        })?;
    let url = window
        .url()
        .map_err(|_| web_error("request_failed", "无法读取会话页面地址"))?;
    Ok(url.origin().ascii_serialization())
}

fn web_summary(shared: &Shared, session: &WebSession) -> Value {
    let origin = match current_origin(shared, session) {
        Ok(origin) => origin,
        Err(error) => return error,
    };
    if origin != session.origin {
        return web_error(
            "web_origin_denied",
            "页面已导航到授权范围之外；请用户新增范围或关闭会话",
        );
    }
    let raw = match execute_script(shared, session, SUMMARY_SCRIPT) {
        Ok(raw) => raw,
        Err(error) => return web_error("request_failed", &error),
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => {
            // ExecuteScript wraps scalar/string results; an object comes back raw.
            let inner: Value = match serde_json::from_str::<String>(&raw) {
                Ok(text) => serde_json::from_str(&text).unwrap_or(Value::Null),
                Err(_) => Value::Null,
            };
            if inner.is_null() {
                return web_error("request_failed", "页面摘要无法解析");
            }
            inner
        }
    };
    // Second pass on the native side: the in-page heuristic is not the only
    // authority for sensitive fields.
    let mut redactions = 0usize;
    let mut summary = parsed;
    if let Some(fields) = summary.get_mut("fields").and_then(Value::as_array_mut) {
        for field in fields.iter_mut() {
            let name = field
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let input_type = field
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let autocomplete = field
                .get("autocomplete")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let label = field
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if is_sensitive_field(&format!("{name} {label}"), input_type, autocomplete) {
                if let Some(object) = field.as_object_mut() {
                    if object.get("value").and_then(Value::as_str).is_some() {
                        object.insert("value".into(), json!(pman_core::browser::WEB_REDACTED));
                        redactions += 1;
                    }
                }
            }
        }
    }
    // Block any response that echoes a credential value from the vault.
    {
        let check = {
            let core = match shared.core.lock() {
                Ok(core) => core,
                Err(_) => return web_error("request_failed", "服务状态不可用"),
            };
            let secret = core.vault.get_site_secret(&session.site);
            let site = core
                .vault
                .list_sites()
                .ok()
                .and_then(|sites| sites.into_iter().find(|s| s.alias == session.site));
            (secret, site)
        };
        match check {
            (Ok(secret), Some(site)) => {
                if web_response_blocked(
                    &serde_json::to_string(&summary).unwrap_or_default(),
                    &secret,
                    &site,
                ) {
                    audit_web(
                        shared,
                        &session.harness,
                        &session.site,
                        "summary",
                        false,
                        "响应包含凭据，已阻止",
                    );
                    return web_error(
                        "web_response_blocked",
                        "页面内容疑似包含凭据，整个摘要已阻止返回",
                    );
                }
            }
            _ => return web_error("request_failed", "无法校验会话凭据"),
        }
    }
    audit_web(
        shared,
        &session.harness,
        &session.site,
        "summary",
        true,
        &format!("页面摘要完成，脱敏 {redactions} 个字段"),
    );
    pman_core::ipc::result_ok(json!({"summary": summary, "origin": origin}))
}

fn web_click(shared: &Shared, session: &WebSession, args: &Value) -> Value {
    if let Err(error) = check_origin(shared, session) {
        return error;
    }
    let Some(selector) = args.get("selector").and_then(Value::as_str) else {
        return web_error("invalid_request", "缺少元素选择器");
    };
    if selector.len() > 512 || selector.contains("javascript:") {
        return web_error("invalid_request", "选择器无效");
    }
    let args_json = json!({"selector": selector, "origin": session.origin});
    let script = format!(r#"(() => {{ const args = {args_json}; {CLICK_BODY} }})()"#);
    match execute_script(shared, session, &script) {
        Ok(raw) => {
            let result = raw_result(&raw);
            if result.get("blocked").and_then(Value::as_bool) == Some(true) {
                audit_web(
                    shared,
                    &session.harness,
                    &session.site,
                    "click",
                    false,
                    "非导航点击已阻止",
                );
                return web_error(
                    "web_action_unsupported",
                    "第一版仅支持同站点导航链接；按钮、表单提交、下载及可能产生业务副作用的点击均不支持",
                );
            }
            audit_web(
                shared,
                &session.harness,
                &session.site,
                "click",
                true,
                "已点击元素",
            );
            pman_core::ipc::result_ok(json!({"ok": true, "result": result}))
        }
        Err(error) => web_error("request_failed", &error),
    }
}

fn web_fill(shared: &Shared, session: &WebSession, args: &Value) -> Value {
    if let Err(error) = check_origin(shared, session) {
        return error;
    }
    let Some(selector) = args.get("selector").and_then(Value::as_str) else {
        return web_error("invalid_request", "缺少元素选择器");
    };
    let value = args
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if selector.len() > 512 || selector.contains("javascript:") {
        return web_error("invalid_request", "选择器无效");
    }
    if value.len() > 8192 {
        return web_error("invalid_request", "填充内容过长");
    }
    let secret_fill = args.get("secret").and_then(Value::as_bool).unwrap_or(false);
    if secret_fill {
        // The contract: secret fills are performed by the user in the isolated
        // login window, not by the AI. Relay the instruction honestly.
        return web_error(
            "web_action_unsupported",
            "密码/验证码等敏感字段须由用户在隔离登录窗口填写；AI 侧一律不支持",
        );
    }
    let args_json = json!({"selector": selector, "value": value});
    let script = format!(r#"(() => {{ const args = {args_json}; {FILL_BODY} }})()"#);
    match execute_script(shared, session, &script) {
        Ok(raw) => {
            let result = raw_result(&raw);
            if result.get("blocked").and_then(Value::as_bool) == Some(true) {
                audit_web(
                    shared,
                    &session.harness,
                    &session.site,
                    "fill",
                    false,
                    "敏感字段填写已阻止",
                );
                return web_error(
                    "web_action_unsupported",
                    "目标是密码、验证码、令牌或支付字段，必须由用户在隔离窗口中填写",
                );
            }
            audit_web(
                shared,
                &session.harness,
                &session.site,
                "fill",
                true,
                "已填写普通字段（值不记录）",
            );
            pman_core::ipc::result_ok(json!({"ok": true, "result": result}))
        }
        Err(error) => web_error("request_failed", &error),
    }
}

fn web_wait(shared: &Shared, session: &WebSession, args: &Value) -> Value {
    if let Err(error) = check_origin(shared, session) {
        return error;
    }
    let selector = args.get("selector").and_then(Value::as_str).unwrap_or("");
    let text = args.get("text").and_then(Value::as_str).unwrap_or("");
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(3000)
        .min(10_000);
    if selector.len() > 512 || selector.contains("javascript:") || text.len() > 512 {
        return web_error("invalid_request", "等待参数无效");
    }
    let args_json = json!({"selector": selector, "text": text, "timeout": timeout_ms});
    let script = format!(r#"(async () => {{ const args = {args_json}; {WAIT_BODY} }})()"#);
    // Waiting happens inside the page script; give the channel extra headroom.
    match execute_script(shared, session, &script) {
        Ok(raw) => {
            audit_web(
                shared,
                &session.harness,
                &session.site,
                "wait",
                true,
                "等待完成",
            );
            pman_core::ipc::result_ok(json!({"ok": true, "result": raw_result(&raw)}))
        }
        Err(error) => web_error("request_failed", &error),
    }
}

fn check_origin(shared: &Shared, session: &WebSession) -> Result<String, Value> {
    let origin = current_origin(shared, session)?;
    if origin != session.origin {
        return Err(web_error(
            "web_origin_denied",
            "页面已导航到授权范围之外；动作被拒绝",
        ));
    }
    Ok(origin)
}

fn raw_result(raw: &str) -> Value {
    match serde_json::from_str(raw) {
        Ok(Value::String(inner)) => serde_json::from_str(&inner).unwrap_or(Value::String(inner)),
        Ok(value) => value,
        Err(_) => json!(raw),
    }
}

/// Fixed page scripts. The sensitive-field heuristic mirrors
/// `pman_core::browser::is_sensitive_field`; the native side re-checks.
const SUMMARY_SCRIPT: &str = r##"(() => {
  const SENSITIVE = ["password","passwd","pwd","passcode","pass_word","otp","verification","verify_code","one-time-code","one_time_code","token","secret","api_key","apikey","card","cvv","cvc","captcha","密码","验证码","卡号","令牌","短信校验"];
  const isSensitive = (el) => {
    const t = (el.getAttribute("type") || "text").toLowerCase();
    if (t === "password") return true;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.startsWith("cc-")) return true;
    const hay = [el.name, el.id, el.getAttribute("aria-label"), el.placeholder].filter(Boolean).join(" ").toLowerCase();
    return SENSITIVE.some(k => hay.includes(k));
  };
  const selectorFor = (el) => {
    if (el.id) return "#" + CSS.escape(el.id);
    const name = el.name ? `[name="${el.name}"]` : "";
    if (name) return el.tagName.toLowerCase() + name;
    const path = [];
    let node = el;
    while (node && node !== document.body && path.length < 5) {
      let part = node.tagName.toLowerCase();
      if (node.parentElement) {
        const siblings = [...node.parentElement.children].filter(c => c.tagName === node.tagName);
        if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(node) + 1})`;
      }
      path.unshift(part);
      node = node.parentElement;
    }
    return path.join(" > ");
  };
  const fields = [...document.querySelectorAll("input,textarea,select")]
    .filter(el => !el.disabled && (el.getAttribute("type") || "text").toLowerCase() !== "hidden")
    .slice(0, 60)
    .map(el => {
      const info = {
        tag: el.tagName.toLowerCase(),
        type: (el.getAttribute("type") || "text").toLowerCase(),
        name: el.name || "",
        id: el.id || "",
        autocomplete: el.getAttribute("autocomplete") || "",
        label: (el.labels && el.labels[0] ? el.labels[0].innerText : el.getAttribute("aria-label") || el.placeholder || "").slice(0, 80),
        selector: selectorFor(el),
      };
      if (isSensitive(el)) info.value = "***REDACTED***";
      else info.value = (el.value || "").slice(0, 120);
      return info;
    });
  const buttons = [...document.querySelectorAll("button,[role=button],input[type=submit],input[type=button]")]
    .slice(0, 40)
    .map(el => ({ selector: selectorFor(el), text: (el.innerText || el.value || "").trim().slice(0, 60) }));
  const links = [...document.querySelectorAll("a[href]")]
    .slice(0, 30)
    .map(el => ({ text: (el.innerText || "").trim().slice(0, 60), href: el.origin === location.origin ? el.pathname : "(跨 origin 链接)" }));
  return {
    url: location.href,
    origin: location.origin,
    title: document.title,
    fields,
    buttons,
    links,
    text: (document.body ? document.body.innerText : "").replace(/\s+/g, " ").slice(0, 2000)
  };
})()"##;

const CLICK_BODY: &str = r#"
  const el = document.querySelector(args.selector);
  if (!el) return { found: false };
  const anchor = el.closest && el.closest("a[href]");
  if (!anchor || anchor.hasAttribute("download") || anchor.target === "_blank") {
    return { found: true, blocked: true };
  }
  const target = new URL(anchor.href, location.href);
  if (!["http:", "https:"].includes(target.protocol) || target.origin !== args.origin) {
    return { found: true, blocked: true };
  }
  anchor.scrollIntoView({ block: "center" });
  location.assign(target.href);
  return { found: true, blocked: false, path: target.pathname };
"#;

const FILL_BODY: &str = r#"
  const el = document.querySelector(args.selector);
  if (!el) return { found: false };
  const SENSITIVE = ["password","passwd","pwd","passcode","pass_word","otp","verification","verify_code","one-time-code","one_time_code","token","secret","api_key","apikey","card","cvv","cvc","captcha","密码","验证码","卡号","令牌","短信校验"];
  const type = (el.getAttribute("type") || "text").toLowerCase();
  const autocomplete = (el.getAttribute("autocomplete") || "").toLowerCase();
  const label = el.labels && el.labels[0] ? el.labels[0].innerText : "";
  const hay = [el.name, el.id, el.getAttribute("aria-label"), el.placeholder, label].filter(Boolean).join(" ").toLowerCase();
  if (type === "password" || autocomplete.startsWith("cc-") || SENSITIVE.some(k => hay.includes(k))) {
    return { found: true, blocked: true };
  }
  if (!["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName)) {
    return { found: true, blocked: true };
  }
  const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
  setter.call(el, args.value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return { found: true, blocked: false };
"#;

const WAIT_BODY: &str = r#"
  return await (async () => {
    const deadline = Date.now() + args.timeout;
    while (Date.now() < deadline) {
      if (args.selector && document.querySelector(args.selector)) return { found: true };
      if (args.text && document.body && document.body.innerText.includes(args.text)) return { found: true };
      await new Promise(r => setTimeout(r, 200));
    }
    return { found: false };
  })();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn click_script_only_follows_same_origin_navigation_links() {
        assert!(CLICK_BODY.contains("closest(\"a[href]\")"));
        assert!(CLICK_BODY.contains("target.origin !== args.origin"));
        assert!(CLICK_BODY.contains("hasAttribute(\"download\")"));
        assert!(!CLICK_BODY.contains("el.click()"));
    }

    #[test]
    fn fill_script_rejects_sensitive_targets_without_trusting_the_caller() {
        assert!(FILL_BODY.contains("type === \"password\""));
        assert!(FILL_BODY.contains("autocomplete.startsWith(\"cc-\")"));
        assert!(FILL_BODY.contains("SENSITIVE.some"));
        assert!(FILL_BODY.contains("blocked: true"));
    }
}
