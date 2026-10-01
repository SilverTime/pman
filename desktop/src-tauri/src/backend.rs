use crate::{
    client_config,
    lifecycle::{ManagementState, Settings},
    platform,
    service::{ensure_main, Shared},
};
use pman_core::{ipc, HttpRequest, SiteInput, SiteMetadataUpdate};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, MutexGuard,
};
use tauri::{Emitter, Manager, State, WebviewWindow};
use zeroize::Zeroizing;

fn admin<'a>(
    window: &WebviewWindow,
    state: &'a Shared,
) -> Result<MutexGuard<'a, ManagementState>, String> {
    ensure_main(window)?;
    let mut guard = state.management.lock().map_err(|_| "管理状态不可用")?;
    guard.require_authenticated()?;
    Ok(guard)
}
fn safe_error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn client(state: &Shared, id: &str) -> Result<Value, String> {
    let clients = state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .list_clients()
        .map_err(safe_error)?;
    let record = clients
        .into_iter()
        .find(|c| c.id == id)
        .ok_or("客户端不存在")?;
    serde_json::to_value(record).map_err(|_| "客户端信息无效".into())
}

#[tauri::command]
pub fn vault_status(window: WebviewWindow, state: State<Shared>) -> Result<Value, String> {
    ensure_main(&window)?;
    state.status()
}
#[tauri::command]
pub fn vault_create(
    password: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    ensure_main(&window)?;
    let password = Zeroizing::new(password);
    if password.chars().count() < 8 {
        return Err("主密码至少需要 8 个字符".into());
    }
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .create(&password)
        .map_err(safe_error)?;
    state.resume_password(&password)
}
#[tauri::command]
pub fn vault_unlock(
    password: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    management_unlock(password, window, state)
}
#[tauri::command]
pub fn vault_lock(window: WebviewWindow, state: State<Shared>) -> Result<(), String> {
    service_pause(window, state)
}
#[tauri::command]
pub fn management_lock(window: WebviewWindow, state: State<Shared>) -> Result<(), String> {
    ensure_main(&window)?;
    state.lock_interface();
    crate::service::close_login_windows(window.app_handle());
    let _ = window.emit("management-locked", ());
    Ok(())
}
#[tauri::command]
pub fn management_unlock(
    password: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    ensure_main(&window)?;
    let password = Zeroizing::new(password);
    let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    core.vault.verify_password(&password).map_err(safe_error)?;
    if !core.vault.unlocked() {
        core.vault.unlock(&password).map_err(safe_error)?;
    }
    management.authenticate();
    Ok(())
}
async fn hello(window: &WebviewWindow, state: &Shared) -> Result<u64, String> {
    ensure_main(window)?;
    let epoch = {
        let guard = state.management.lock().map_err(|_| "管理状态不可用")?;
        if !guard.persistent.settings.hello_enabled {
            return Err("Windows Hello 尚未启用".into());
        }
        guard.auth_epoch
    };
    #[cfg(windows)]
    let hwnd = window.hwnd().map_err(|_| "无法验证管理窗口")?.0 as isize;
    #[cfg(not(windows))]
    let hwnd = 0isize;
    tauri::async_runtime::spawn_blocking(move || platform::verify_hello(hwnd))
        .await
        .map_err(|_| "身份验证未完成")??;
    Ok(epoch)
}
#[tauri::command]
pub async fn management_unlock_hello(
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let epoch = hello(&window, &state).await?;
    state.unlock_protected(false, Some(epoch))
}
#[tauri::command]
pub fn service_pause(window: WebviewWindow, state: State<Shared>) -> Result<(), String> {
    ensure_main(&window)?;
    state.pause()?;
    crate::service::close_login_windows(window.app_handle());
    let _ = window.emit("management-locked", ());
    let _ = window.emit("service-changed", ());
    Ok(())
}
#[tauri::command]
pub async fn service_resume(
    password: Option<String>,
    hello: Option<bool>,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<(), String> {
    ensure_main(&window)?;
    if hello.unwrap_or(false) {
        let epoch = self::hello(&window, &state).await?;
        state.unlock_protected(true, Some(epoch))
    } else {
        let password = Zeroizing::new(password.ok_or("请输入主密码")?);
        state.resume_password(&password)
    }
}
#[tauri::command]
pub fn settings_get(window: WebviewWindow, state: State<Shared>) -> Result<Settings, String> {
    ensure_main(&window)?;
    Ok(state
        .management
        .lock()
        .map_err(|_| "管理状态不可用")?
        .persistent
        .settings
        .clone())
}
#[tauri::command]
pub fn settings_update(
    settings: Settings,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let mut guard = admin(&window, &state)?;
    if !matches!(settings.theme.as_str(), "dark" | "light") || settings.idle_lock_minutes > 1440 {
        return Err("设置值无效".into());
    }
    platform::set_autostart(
        settings.autostart,
        &std::env::current_exe().map_err(|_| "无法定位安装目录")?,
    )?;
    let old = guard.persistent.settings.clone();
    guard.persistent.settings = settings;
    if let Err(e) = guard.save() {
        guard.persistent.settings = old;
        return Err(e);
    }
    Ok(())
}
#[tauri::command]
pub fn window_hide(window: WebviewWindow) -> Result<(), String> {
    ensure_main(&window)?;
    window.hide().map_err(|_| "无法隐藏窗口".into())
}
#[tauri::command]
pub fn application_exit(
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: State<Shared>,
    exit: State<Arc<AtomicBool>>,
) -> Result<(), String> {
    ensure_main(&window)?;
    state.pause()?;
    exit.store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub fn list_sites(window: WebviewWindow, state: State<Shared>) -> Result<Vec<Value>, String> {
    let _guard = admin(&window, &state)?;
    let core = state.core.lock().map_err(|_| "服务状态不可用")?;
    let statuses = core.vault.connection_statuses().map_err(safe_error)?;
    core.vault
        .list_sites()
        .map_err(safe_error)?
        .into_iter()
        .map(|site| {
            let details = core.vault.details(&site.alias).map_err(safe_error)?;
            let mut value = serde_json::to_value(&site).map_err(|_| "无法读取连接")?;
            if let Some(status) = details.extra.get("status") {
                value["status"] = status.clone();
            }
            if let Some(checked) = details.extra.get("checked_at") {
                value["last_checked_at"] = checked.clone();
            }
            value["details"] = serde_json::to_value(details).map_err(|_| "无法读取连接")?;
            if let Some(dimensions) = statuses.iter().find(|s| s.alias == site.alias) {
                value["dimensions"] =
                    serde_json::to_value(dimensions).map_err(|_| "无法读取连接状态")?;
            }
            Ok(value)
        })
        .collect()
}

/// Five-dimension status report for one connection, merged with the service
/// state so the UI can keep "管理界面已锁定" and "API 可用" separate.
#[tauri::command]
pub fn connection_status(
    alias: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    let core = state.core.lock().map_err(|_| "服务状态不可用")?;
    let running = core.vault.unlocked();
    let mut status =
        serde_json::to_value(core.vault.connection_status(&alias).map_err(safe_error)?)
            .map_err(safe_error)?;
    let management = state.management.lock().map_err(|_| "管理状态不可用")?;
    status["service"] = json!({
        "management_locked": !management.authenticated,
        "service_paused": management.persistent.service_paused,
        "service_running": running && !management.persistent.service_paused,
    });
    Ok(status)
}
#[tauri::command]
pub fn site_add(
    mut input: Value,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let details = input
        .as_object_mut()
        .and_then(|o| o.remove("details"))
        .unwrap_or(json!({"ai_enabled":false}));
    let parsed: SiteInput = serde_json::from_value(input).map_err(|_| "凭据格式无效")?;
    let alias = parsed.alias.clone();
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    core.vault.add_site(parsed).map_err(safe_error)?;
    if let Err(e) = core.vault.update_details(&alias, details) {
        let _ = core.vault.remove_site(&alias);
        return Err(e.to_string());
    }
    Ok(())
}
#[tauri::command]
pub fn site_update_metadata(
    alias: String,
    site_url: String,
    name: Option<String>,
    purpose: Option<String>,
    tags: Vec<String>,
    details: Option<Value>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    let previous = core
        .vault
        .list_sites()
        .map_err(safe_error)?
        .into_iter()
        .find(|s| s.alias == alias)
        .ok_or("连接不存在")?;
    if previous.site_url != site_url
        && core
            .vault
            .details(&alias)
            .map_err(safe_error)?
            .extra
            .get("account_id")
            .is_some()
    {
        return Err("此连接已绑定登录账号，请新增连接以使用其他环境".into());
    }
    core.vault
        .update_site_metadata(
            &alias,
            SiteMetadataUpdate {
                site_url,
                name,
                purpose,
                tags,
            },
        )
        .map_err(safe_error)?;
    if let Some(details) = details {
        core.vault
            .update_details(&alias, details)
            .map_err(safe_error)?;
    }
    Ok(())
}
#[tauri::command]
pub fn site_rotate(
    alias: String,
    secret: Value,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .rotate_secret(&alias, secret)
        .map_err(safe_error)
}
#[tauri::command]
pub fn site_remove(
    alias: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .remove_site(&alias)
        .map_err(safe_error)?;
    // A deleted connection cannot keep web sessions.
    state.close_web_session_windows(state.web_sessions.close_for_site(&alias));
    Ok(())
}
#[tauri::command]
pub fn site_reveal(
    alias: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .get_site_secret(&alias)
        .map_err(safe_error)
}
#[tauri::command]
pub fn site_copy(
    alias: String,
    field: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let secret = state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .get_site_secret(&alias)
        .map_err(safe_error)?;
    let value = secret.get(&field).ok_or("该字段不可复制")?;
    let text = Zeroizing::new(match value {
        Value::String(v) => v.clone(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).map_err(|_| "该字段不可复制")?
        }
        _ => return Err("该字段不可复制".into()),
    });
    platform::copy_secret(&text)
}
#[tauri::command]
pub fn generate_password(
    length: Option<usize>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<String, String> {
    let _guard = admin(&window, &state)?;
    use rand::Rng;
    let length = length.unwrap_or(24);
    if !(12..=128).contains(&length) {
        return Err("密码长度应为 12 至 128 位".into());
    }
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_+=";
    let mut rng = rand::rngs::OsRng;
    Ok((0..length)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect())
}

#[tauri::command]
pub fn list_harnesses(window: WebviewWindow, state: State<Shared>) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .list_harnesses()
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn ensure_harness(
    name: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .ensure_harness(&name)
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn delete_harness(
    name: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .delete_harness(&name)
        .map_err(safe_error)
}
#[tauri::command]
pub fn set_harness_policy(
    name: String,
    policy: Value,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .set_policy(&name, policy)
        .map_err(safe_error)
}
#[tauri::command]
pub fn add_harness_allow_rule(
    name: String,
    site: String,
    method: String,
    path: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .add_allow_rule(&name, &site, &method, &path)
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn remove_harness_allow_rule(
    name: String,
    rule: Value,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .remove_allow_rule(&name, rule)
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn grant_connection(
    site: String,
    client_ids: Vec<String>,
    site_url: String,
    account: String,
    tenant: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    let connection = core
        .vault
        .list_sites()
        .map_err(safe_error)?
        .into_iter()
        .find(|item| item.alias == site)
        .ok_or("连接不存在")?;
    let details = core.vault.details(&site).map_err(safe_error)?;
    if connection.site_url != site_url || details.account != account || details.tenant != tenant {
        return Err("连接账号已变化，请刷新后重新确认授权".into());
    }
    // Validate every selected client up front so a failure can name the tool
    // by its display name (never by identity material) before any write.
    for id in &client_ids {
        let record = core
            .vault
            .list_clients()
            .map_err(safe_error)?
            .into_iter()
            .find(|client| client.id == *id)
            .ok_or("客户端不存在，授权未保存；请刷新后重试")?;
        let expired = record.expires_at.as_deref().is_some_and(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .map(|parsed| parsed <= chrono::Utc::now())
                .unwrap_or(true)
        });
        if !record.paired || record.revoked_at.is_some() || expired {
            return Err(format!(
                "客户端「{}」已失效，授权未保存；请取消勾选后重试",
                record.name
            ));
        }
    }
    core.vault
        .grant_connection_clients(&site, &client_ids)
        .map_err(safe_error)
}

#[tauri::command]
pub fn grant_add(
    harness: String,
    site: String,
    method: String,
    path: String,
    capability: Option<String>,
    constraints: Option<Value>,
    expires_at: Option<String>,
    operation: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    if !matches!(operation.as_str(), "query" | "write") {
        return Err("操作类型无效".into());
    }
    if let Some(expiry) = &expires_at {
        let date = chrono::DateTime::parse_from_rfc3339(expiry).map_err(|_| "授权到期时间无效")?;
        if date <= chrono::Utc::now() {
            return Err("授权到期时间必须晚于现在".into());
        }
    }
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    if !core.vault.details(&site).map_err(safe_error)?.ai_enabled {
        return Err("请先将此连接设为允许 AI 使用，再配置客户端范围".into());
    }
    core.vault.ensure_harness(&harness).map_err(safe_error)?;
    let mut policy = core.vault.get_policy(&harness).map_err(safe_error)?;
    let mut rule = json!({"site":site,"methods":[method.to_uppercase()],"paths":[path],"operation":operation,"require_approval":false});
    if let Some(capability) = capability.filter(|value| !value.trim().is_empty()) {
        rule["capability"] = capability.trim().into();
    }
    if let Some(constraints) =
        constraints.filter(|value| value.as_object().is_some_and(|value| !value.is_empty()))
    {
        rule["constraints"] = constraints;
    }
    if let Some(expiry) = expires_at {
        rule["expires_at"] = expiry.into();
    }
    if !policy["allow"].is_array() {
        policy["allow"] = json!([]);
    }
    policy["allow"].as_array_mut().unwrap().push(rule);
    pman_core::Policy::from_json(&policy).map_err(safe_error)?;
    core.vault.set_policy(&harness, policy).map_err(safe_error)
}
#[tauri::command]
pub fn list_approvals(
    status: Option<String>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .list_approvals(status.as_deref().unwrap_or("pending"))
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn assistance_list(
    status: Option<String>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .list_assistance(status.as_deref())
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn assistance_decide(
    id: String,
    status: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .decide_assistance(&id, &status)
        .map_err(safe_error)?;
    let _ = window.emit("approvals-changed", ());
    Ok(json!({"id":id,"status":status}))
}
#[tauri::command]
pub fn decide_approval(
    id: String,
    approve: bool,
    persistent: Option<bool>,
    decided_by: Option<String>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    let _ = decided_by;
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    let result = if approve && persistent.unwrap_or(false) {
        core.vault
            .approve_persistently(&id, "desktop")
            .map_err(safe_error)?
    } else {
        core.vault
            .decide_approval(&id, approve, "desktop")
            .map_err(safe_error)?
    };
    serde_json::to_value(result).map_err(safe_error)
}
#[tauri::command]
pub fn list_audit(
    harness: Option<String>,
    limit: Option<i64>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .query_audit(harness.as_deref(), limit.unwrap_or(500).clamp(1, 2000))
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub async fn broker_call(
    request: HttpRequest,
    harness: Option<String>,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    state.require_management()?;
    let shared = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        shared.http(
            request,
            harness.as_deref().unwrap_or("desktop-preview"),
            None,
        )
    })
    .await
    .map_err(|_| "请求执行失败")?;
    state.require_management()?;
    serde_json::to_value(result).map_err(safe_error)
}

/// Read-only connection check. Runs through the shared proxy chain (never
/// from the webview), writes only sanitized evidence, and keeps the service
/// lock released while the network request is in flight. This is the
/// connection check; `client_test` is the separate AI client check.
#[tauri::command]
pub async fn connection_check(
    alias: String,
    check_path: Option<String>,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    use std::time::Duration;
    ensure_main(&window)?;
    let auth_epoch = crate::login::begin_management(&state)?;
    let (plan, generation) = {
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        let plan = core
            .vault
            .prepare_connection_check(&alias, check_path.as_deref())
            .map_err(safe_error)?;
        (plan, core.vault.generation())
    };
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        pman_core::execute_connection_check(&plan, Duration::from_secs(15))
    })
    .await
    .map_err(|_| "连接检查失败")?;
    ensure_main(&window)?;
    let response = {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        crate::login::ensure_epoch(&mut management, auth_epoch)?;
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        if generation != core.vault.generation() {
            return Err("检查期间连接或授权发生变化，请重新检查".into());
        }
        core.vault
            .finish_connection_check(&alias, &outcome)
            .map_err(safe_error)?;
        serde_json::to_value(core.vault.connection_status(&alias).map_err(safe_error)?)
            .map_err(safe_error)?
    };
    let _ = window.app_handle().emit("connections-changed", ());
    Ok(json!({"outcome": outcome, "dimensions": response}))
}

#[tauri::command]
pub fn clients_list(window: WebviewWindow, state: State<Shared>) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    serde_json::to_value(
        state
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .list_clients()
            .map_err(safe_error)?,
    )
    .map_err(safe_error)
}
#[tauri::command]
pub fn client_pair(
    name: String,
    kind: String,
    harness: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    if !matches!(kind.as_str(), "codex" | "claude" | "generic") {
        return Err("客户端类型无效".into());
    }
    let id = format!("client-{}", uuid::Uuid::new_v4().simple());
    let verifier = ipc::create_pairing(&id).map_err(|_| "无法保护客户端配对信息")?;
    let result = state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .pair_client_for(&name, &kind, &harness, &id, &verifier);
    if result.is_err() {
        let _ = ipc::remove_pairing(&id);
    }
    serde_json::to_value(result.map_err(safe_error)?).map_err(safe_error)
}
#[tauri::command]
pub fn client_revoke(
    id: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let harness = {
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        let harness = core
            .vault
            .list_clients()
            .map_err(safe_error)?
            .into_iter()
            .find(|client| client.id == id)
            .map(|client| client.harness);
        core.vault.revoke_client(&id).map_err(safe_error)?;
        harness
    };
    // Revoked clients lose their web sessions immediately.
    if let Some(harness) = harness {
        state.close_web_session_windows(state.web_sessions.close_for_harness(&harness));
    }
    ipc::remove_pairing(&id).map_err(|_| "授权已撤销，本机旧配对文件未能移除".into())
}
#[tauri::command]
pub fn client_config_preview(
    id: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<client_config::ConfigPreview, String> {
    let _guard = admin(&window, &state)?;
    client_config::preview(&client(&state, &id)?, &state.home)
}
#[tauri::command]
pub fn client_config_apply(
    id: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<client_config::ConfigResult, String> {
    let _guard = admin(&window, &state)?;
    let c = client(&state, &id)?;
    if c["revoked_at"].is_string() {
        return Err("此客户端已撤销，请重新配对".into());
    }
    client_config::apply(&c, &state.home)
}
#[tauri::command]
pub fn client_config_restore(
    id: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<client_config::ConfigResult, String> {
    let _guard = admin(&window, &state)?;
    client_config::restore(&client(&state, &id)?, &state.home)
}
/// Connection-level web-capability switch (BROWSER-CONTRACT.md). Enabling
/// never grants a client; per-client web rules are a separate step.
#[tauri::command]
pub fn web_enable(
    alias: String,
    enabled: bool,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    core.vault
        .set_web_enabled(&alias, enabled)
        .map_err(safe_error)?;
    if !enabled {
        drop(core);
        state.close_web_session_windows(state.web_sessions.close_for_site(&alias));
    }
    Ok(())
}

/// Per-client browser authorization with explicit origins.
#[tauri::command]
pub fn grant_web_clients(
    site: String,
    client_ids: Vec<String>,
    origins: Vec<String>,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<(), String> {
    let _guard = admin(&window, &state)?;
    let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
    core.vault
        .grant_web_clients(&site, &client_ids, &origins)
        .map_err(safe_error)
}

/// Stop all web sessions of a connection (human control entry point).
#[tauri::command]
pub fn web_sessions_stop(
    alias: String,
    window: WebviewWindow,
    state: State<Shared>,
) -> Result<Value, String> {
    let _guard = admin(&window, &state)?;
    let closed = state.web_sessions.close_for_site(&alias);
    let count = closed.len();
    state.close_web_session_windows(closed);
    Ok(json!({"closed": count}))
}

/// Identity/capability handshake through the real pairing channel (DPAPI
/// capability file + named pipe). It proves local pairing and proxy health
/// and lists granted connections; it is never a claim that the AI tool has
/// made a real business call — that evidence comes from the audit log.
#[tauri::command]
pub async fn client_handshake(
    id: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    state.require_management()?;
    let client = client(&state, &id)?;
    let harness = client["harness"].as_str().unwrap_or_default().to_owned();
    if client["revoked_at"].is_string() {
        return Err("此客户端已撤销，请重新配对".into());
    }
    let result =
        tauri::async_runtime::spawn_blocking(move || ipc::call(&id, "handshake", json!({})))
            .await
            .map_err(|_| "握手检查失败")?
            .map_err(|_| "原生代理连接失败，请检查配对和服务状态")?;
    state.require_management()?;
    Ok(json!({
        "ok": result["ok"] == true,
        "harness": result.get("harness").and_then(Value::as_str).unwrap_or(&harness),
        "connections": result.get("connections").cloned().unwrap_or(json!([])),
        "identity_last_used_at": result
            .get("identity_last_used_at")
            .cloned()
            .unwrap_or(Value::Null),
        "message": if result["ok"] == true {
            "身份握手成功：本机配对与代理通道正常"
        } else {
            "客户端身份验证失败"
        },
    }))
}

#[tauri::command]
pub async fn client_test(
    id: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    state.require_management()?;
    let result = tauri::async_runtime::spawn_blocking(move || ipc::call(&id, "status", json!({})))
        .await
        .map_err(|_| "连通性检查失败")?
        .map_err(|_| "原生代理连接失败，请检查配对和服务状态")?;
    state.require_management()?;
    Ok(
        json!({"ok":result["ok"]==true&&result["service_running"]==true,"message":if result["ok"]!=true{"客户端身份验证失败"}else if result["service_running"]==true{"本机配对和代理连接正常；请在 AI 客户端刷新 MCP 工具"}else{"客户端已配对，但服务处于暂停或未解锁状态"}}),
    )
}
