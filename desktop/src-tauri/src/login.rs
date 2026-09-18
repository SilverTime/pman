//! Human-only login management. Remote login windows have no management capability.
use crate::service::{ensure_main, LoginBinding, PendingE10, Shared};
use pman_core::{
    e10::{self, E10AccountMetadata, E10AuthFlow, E10AuthStart, E10Error},
    SiteSummary, Vault,
};
use serde_json::{json, Value};
use std::{sync::atomic::Ordering, time::Duration};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

fn login_error(error: E10Error) -> String {
    format!("{}: {}", error.code(), error)
}

fn origin(url: &str) -> Result<String, String> {
    let parsed = tauri::Url::parse(url).map_err(|_| "登录地址无效")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str().is_none()
    {
        return Err("登录地址必须是不包含认证信息的 HTTP 或 HTTPS 地址".into());
    }
    Ok(parsed.origin().ascii_serialization())
}

pub(crate) fn begin_management(state: &Shared) -> Result<u64, String> {
    let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
    management.require_authenticated()?;
    if management.persistent.service_paused {
        return Err("service_paused: AI 服务已暂停".into());
    }
    Ok(management.auth_epoch)
}

pub(crate) fn ensure_epoch(
    management: &mut crate::lifecycle::ManagementState,
    epoch: u64,
) -> Result<(), String> {
    management.require_authenticated()?;
    if management.auth_epoch != epoch {
        return Err("stale_login: 管理界面曾锁定，请重新开始登录".into());
    }
    if management.persistent.service_paused {
        return Err("service_paused: AI 服务已暂停".into());
    }
    Ok(())
}

fn bound_site(
    vault: &Vault,
    alias: &str,
    expected_origin: &str,
    generation: Option<u64>,
) -> Result<SiteSummary, String> {
    if !vault.unlocked() {
        return Err("service_paused: 请先恢复 AI 服务".into());
    }
    if generation.is_some_and(|generation| generation != vault.generation()) {
        return Err("stale_login: 登录期间连接或授权发生变化，请重新开始登录".into());
    }
    let site = vault
        .list_sites()
        .map_err(|_| "无法读取连接")?
        .into_iter()
        .find(|site| site.alias == alias)
        .ok_or("连接不存在或已删除")?;
    if origin(&site.site_url)? != expected_origin {
        return Err("origin_mismatch: 登录目标与连接环境不一致".into());
    }
    if !matches!(site.auth_type.as_str(), "e10" | "login" | "cookie_jar") {
        return Err("该连接类型不支持网站登录".into());
    }
    Ok(site)
}

fn record_metadata(
    vault: &mut Vault,
    alias: &str,
    metadata: &E10AccountMetadata,
) -> Result<(), String> {
    let mut extra = vault.details(alias).map_err(|_| "无法读取账号信息")?.extra;
    if !extra.is_object() {
        extra = json!({});
    }
    let value = serde_json::to_value(metadata).map_err(|_| "无法保存账号信息")?;
    for (key, value) in value.as_object().ok_or("账号信息无效")? {
        extra[key] = value.clone();
    }
    extra["last_checked_at"] = json!(metadata.checked_at);
    vault.update_details(alias, json!({"account":if metadata.user_name.is_empty(){&metadata.user_id}else{&metadata.user_name},
        "environment":metadata.origin,"tenant":if metadata.tenant_name.is_empty(){&metadata.tenant_key}else{&metadata.tenant_name},"extra":extra}))
        .map_err(|_| "无法保存账号信息")?;
    Ok(())
}

fn ensure_account(vault: &Vault, alias: &str, metadata: &E10AccountMetadata) -> Result<(), String> {
    let details = vault.details(alias).map_err(|_| "无法读取连接账号")?;
    let secret = vault
        .get_site_secret(alias)
        .map_err(|_| "无法确认连接账号")?;
    if secret
        .get("account_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty() && id != metadata.account_id)
    {
        return Err("account_mismatch: 当前账号与连接绑定账号不一致；请为其他账号新建连接".into());
    }
    if details
        .extra
        .get("account_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty() && id != metadata.account_id)
    {
        return Err("account_mismatch: 当前账号与连接绑定账号不一致；请为其他账号新建连接".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn open_login_window(
    app: AppHandle,
    alias: String,
    site_url: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    let auth_epoch = begin_management(&state)?;
    let target = origin(&site_url)?;
    let (site, generation) = {
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        (
            bound_site(&core.vault, &alias, &target, None)?,
            core.vault.generation(),
        )
    };
    if site.auth_type == "e10" {
        e10::normalize_origin(&target).map_err(login_error)?;
    }
    let label = format!("login-{}", uuid::Uuid::new_v4());
    // Stable native site IDs cannot be supplied by remote web content.
    let profile = state.home.join("login-profiles").join(&site.id);
    let login = WebviewWindowBuilder::new(
        &app,
        &label,
        WebviewUrl::External(tauri::Url::parse(&site_url).map_err(|_| "登录地址无效")?),
    )
    .title(format!("pman · 登录 {}", site.alias))
    .inner_size(1040.0, 760.0)
    .data_directory(profile)
    .on_navigation(|url| matches!(url.scheme(), "http" | "https"))
    .build()
    .map_err(|_| "无法打开独立登录窗口")?;
    let final_check = (|| {
        ensure_main(&window)?;
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        bound_site(&core.vault, &alias, &target, Some(generation))?;
        state
            .browser_logins
            .lock()
            .map_err(|_| "登录状态不可用")?
            .insert(
                label.clone(),
                LoginBinding {
                    alias: alias.clone(),
                    origin: target,
                    label: label.clone(),
                    generation,
                    auth_epoch,
                },
            );
        Ok::<(), String>(())
    })();
    if let Err(error) = final_check {
        let _ = login.close();
        return Err(error);
    }
    let cleanup = state.inner().clone();
    let cleanup_label = label.clone();
    login.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            if let Ok(mut logins) = cleanup.browser_logins.lock() {
                logins.remove(&cleanup_label);
            }
        }
    });
    Ok(json!({"label":label,"url":site_url}))
}

#[tauri::command]
pub async fn login_capture_cookies(
    app: AppHandle,
    alias: String,
    label: String,
    site_url: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    let current_epoch = begin_management(&state)?;
    let target = origin(&site_url)?;
    let (generation, auth_epoch) = {
        let logins = state.browser_logins.lock().map_err(|_| "登录状态不可用")?;
        let binding = logins.get(&label).ok_or("登录窗口不存在或已关闭")?;
        if binding.alias != alias || binding.origin != target || binding.label != label {
            return Err("登录窗口与连接不匹配".into());
        }
        if binding.auth_epoch != current_epoch {
            return Err("stale_login: 管理界面曾锁定，请重新开始登录".into());
        }
        (binding.generation, binding.auth_epoch)
    };
    let (site, previous) = {
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        (
            bound_site(&core.vault, &alias, &target, Some(generation))?,
            core.vault
                .get_site_secret(&alias)
                .map_err(|_| "无法读取连接")?,
        )
    };
    let login = app.get_webview_window(&label).ok_or("登录窗口已关闭")?;
    if origin(login.url().map_err(|_| "无法确认登录窗口地址")?.as_str())? != target {
        return Err("登录仍在其他站点，请完成登录并返回目标环境后再保存".into());
    }
    let cookie_window = login.clone();
    let cookie_origin = target.clone();
    let cookies = tauri::async_runtime::spawn_blocking(move || {
        let host = tauri::Url::parse(&cookie_origin).map_err(|_| "登录地址无效")?.host_str().ok_or("登录地址无效")?.to_owned();
        let cookies = cookie_window.cookies().map_err(|_| "无法读取独立登录窗口的会话")?;
        let mut records = Vec::new();
        for cookie in cookies {
            let domain = cookie.domain().unwrap_or(&host);
            let normalized = domain.trim_start_matches('.');
            if normalized != host && !(domain.starts_with('.') && host.ends_with(&format!(".{normalized}"))) { continue; }
            records.push(json!({"name":cookie.name(),"value":cookie.value(),"domain":domain,"path":cookie.path().unwrap_or("/"),
                "expires":cookie.expires_datetime().map(|time|time.unix_timestamp()),"secure":cookie.secure().unwrap_or(false),
                "http_only":cookie.http_only().unwrap_or(false),"host_only":!domain.starts_with('.')}));
        }
        Ok::<Vec<Value>,String>(records)
    }).await.map_err(|_| "无法读取登录会话")??;
    if cookies.is_empty() {
        return Err("未找到目标环境的登录会话，请完成登录后再保存".into());
    }
    let names: Vec<String> = cookies
        .iter()
        .filter_map(|cookie| {
            cookie
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut secret = json!({"cookies":cookies,"origin":target});
    let metadata = if site.auth_type == "e10" {
        secret["agent_type"] = previous
            .get("agent_type")
            .cloned()
            .unwrap_or(json!("Codex"));
        if let Some(id) = previous.get("account_id") {
            secret["account_id"] = id.clone();
        }
        let health_origin = target.clone();
        let health_secret = secret.clone();
        Some(
            tauri::async_runtime::spawn_blocking(move || {
                e10::check_session(&health_origin, &health_secret)
            })
            .await
            .map_err(|_| "登录检查失败")?
            .map_err(login_error)?,
        )
    } else {
        None
    };
    ensure_main(&window)?;
    {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        let logins = state.browser_logins.lock().map_err(|_| "登录状态不可用")?;
        if !logins.contains_key(&label) {
            return Err("登录窗口已关闭，未保存会话".into());
        }
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        bound_site(&core.vault, &alias, &target, Some(generation))?;
        if let Some(metadata) = &metadata {
            ensure_account(&core.vault, &alias, metadata)?;
            secret["account_id"] = json!(metadata.account_id);
        }
        core.vault
            .update_secret(&alias, secret)
            .map_err(|_| "无法保存登录会话")?;
        if let Some(metadata) = &metadata {
            record_metadata(&mut core.vault, &alias, metadata)?;
        } else {
            let mut extra = core
                .vault
                .details(&alias)
                .map_err(|_| "无法读取连接")?
                .extra;
            if !extra.is_object() {
                extra = json!({});
            }
            extra["status"] = json!("unverified");
            core.vault
                .update_details(&alias, json!({"extra":extra}))
                .map_err(|_| "无法保存连接状态")?;
        }
    }
    state
        .browser_logins
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&label);
    let _ = login.close();
    let _ = app.emit("connections-changed", ());
    Ok(json!({"alias":alias,"cookie_count":names.len(),"cookie_names":names,"saved":true}))
}

#[tauri::command]
pub fn close_login_window(
    app: AppHandle,
    label: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<(), String> {
    ensure_main(&window)?;
    state.require_management()?;
    if state
        .browser_logins
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&label)
        .is_none()
    {
        return Err("登录窗口不存在".into());
    }
    if let Some(login) = app.get_webview_window(&label) {
        login.close().map_err(|_| "无法关闭登录窗口")?;
    }
    Ok(())
}

#[tauri::command]
pub async fn e10_begin(
    _app: AppHandle,
    alias: String,
    site_url: String,
    agent_type: String,
    pkce_verified: bool,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<E10AuthStart, String> {
    ensure_main(&window)?;
    let auth_epoch = begin_management(&state)?;
    let target = e10::normalize_origin(&site_url).map_err(login_error)?;
    let generation = {
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        if bound_site(&core.vault, &alias, &target, None)?.auth_type != "e10" {
            return Err("该连接不是 E10 账号".into());
        }
        core.vault.generation()
    };
    let flow = E10AuthFlow::begin(&target, &agent_type, pkce_verified).map_err(login_error)?;
    let info = flow.info();
    {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        bound_site(
            &state.core.lock().map_err(|_| "服务状态不可用")?.vault,
            &alias,
            &target,
            Some(generation),
        )?;
        let mut flows = state.e10_flows.lock().map_err(|_| "登录状态不可用")?;
        let expired: Vec<String> = flows
            .iter()
            .filter(|(_, pending)| {
                pending.flow.as_ref().is_some_and(|flow| {
                    chrono::DateTime::parse_from_rfc3339(&flow.info().expires_at)
                        .is_ok_and(|expires| expires < chrono::Utc::now())
                })
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            flows.remove(&id);
            if let Some(cancel) = state
                .e10_cancellations
                .lock()
                .map_err(|_| "登录状态不可用")?
                .remove(&id)
            {
                cancel.store(true, Ordering::SeqCst);
            }
        }
        if flows.values().any(|pending| pending.alias == alias) {
            return Err("此连接已有登录正在进行，请先完成或取消".into());
        }
        state
            .e10_cancellations
            .lock()
            .map_err(|_| "登录状态不可用")?
            .insert(info.session_id.clone(), flow.cancellation());
        flows.insert(
            info.session_id.clone(),
            PendingE10 {
                alias,
                origin: target,
                flow: Some(flow),
                generation,
                auth_epoch,
            },
        );
    }
    if crate::native_dialogs::open_external_url(&info.authorize_url).is_err() {
        state
            .e10_flows
            .lock()
            .map_err(|_| "登录状态不可用")?
            .remove(&info.session_id);
        if let Some(cancel) = state
            .e10_cancellations
            .lock()
            .map_err(|_| "登录状态不可用")?
            .remove(&info.session_id)
        {
            cancel.store(true, Ordering::SeqCst);
        }
        return Err("无法打开系统浏览器".into());
    }
    Ok(info)
}

#[tauri::command]
pub async fn e10_complete(
    app: AppHandle,
    session_id: String,
    alias: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    let current_epoch = begin_management(&state)?;
    let (target, generation, auth_epoch, flow) = {
        let mut flows = state.e10_flows.lock().map_err(|_| "登录状态不可用")?;
        if flows
            .get(&session_id)
            .is_none_or(|pending| pending.alias != alias || pending.auth_epoch != current_epoch)
        {
            return Err("登录事务不存在或与连接不匹配".into());
        }
        let pending = flows.get_mut(&session_id).ok_or("登录事务已结束")?;
        (
            pending.origin.clone(),
            pending.generation,
            pending.auth_epoch,
            pending.flow.take().ok_or("该登录事务已在处理中")?,
        )
    };
    let outcome =
        tauri::async_runtime::spawn_blocking(move || flow.complete(Duration::from_secs(600))).await;
    state
        .e10_flows
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&session_id);
    let cancelled = state
        .e10_cancellations
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&session_id)
        .is_none_or(|cancel| cancel.load(Ordering::SeqCst));
    if cancelled {
        return Err("cancelled: 登录已取消，未保存会话".into());
    }
    let mut result = outcome.map_err(|_| "登录检查失败")?.map_err(login_error)?;
    ensure_main(&window)?;
    {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        bound_site(&core.vault, &alias, &target, Some(generation))?;
        ensure_account(&core.vault, &alias, &result.metadata)?;
        result.secret["account_id"] = json!(result.metadata.account_id);
        core.vault
            .update_secret(&alias, result.secret)
            .map_err(|_| "无法保存登录会话")?;
        record_metadata(&mut core.vault, &alias, &result.metadata)?;
    }
    let _ = app.emit("connections-changed", ());
    Ok(
        json!({"status":"connected","last_checked_at":result.metadata.checked_at,"account":result.metadata.user_name,
        "tenant":result.metadata.tenant_name,"message":"E10 登录与账号身份已验证"}),
    )
}

#[tauri::command]
pub fn e10_cancel(
    session_id: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<(), String> {
    ensure_main(&window)?;
    state.require_management()?;
    if let Some(cancel) = state
        .e10_cancellations
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&session_id)
    {
        cancel.store(true, Ordering::SeqCst);
    }
    state
        .e10_flows
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&session_id);
    Ok(())
}

#[tauri::command]
pub async fn e10_check(
    app: AppHandle,
    alias: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    ensure_main(&window)?;
    let auth_epoch = begin_management(&state)?;
    let (target, secret, generation) = {
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        let site = core
            .vault
            .list_sites()
            .map_err(|_| "无法读取连接")?
            .into_iter()
            .find(|site| site.alias == alias)
            .ok_or("连接不存在")?;
        let target = e10::normalize_origin(&site.site_url).map_err(login_error)?;
        if bound_site(&core.vault, &alias, &target, None)?.auth_type != "e10" {
            return Err("该连接不是 E10 账号".into());
        }
        (
            target,
            core.vault
                .get_site_secret(&alias)
                .map_err(|_| "无法读取连接")?,
            core.vault.generation(),
        )
    };
    let health_origin = target.clone();
    let outcome =
        tauri::async_runtime::spawn_blocking(move || e10::check_session(&health_origin, &secret))
            .await
            .map_err(|_| "连接检查失败")?;
    ensure_main(&window)?;
    let response = {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        bound_site(&core.vault, &alias, &target, Some(generation))?;
        match outcome {
            Ok(metadata) => {
                ensure_account(&core.vault, &alias, &metadata)?;
                record_metadata(&mut core.vault, &alias, &metadata)?;
                core.vault
                    .finish_e10_evidence(
                        &alias,
                        "verified",
                        Some(&metadata.user_name),
                        "连接正常",
                        None,
                    )
                    .map_err(|_| "无法保存检查状态")?;
                json!({"status":"connected","last_checked_at":metadata.checked_at,"account":metadata.user_name,"tenant":metadata.tenant_name,"message":"连接正常"})
            }
            Err(error) => {
                let checked_at = chrono::Utc::now().to_rfc3339();
                core.vault
                    .finish_e10_evidence(
                        &alias,
                        error.code(),
                        None,
                        &error.to_string(),
                        Some(error.code()),
                    )
                    .map_err(|_| "无法保存检查状态")?;
                json!({"status":error.code(),"last_checked_at":checked_at,"message":error.to_string()})
            }
        }
    };
    let _ = app.emit("connections-changed", ());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_lock_then_reauthentication_invalidates_old_login_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let mut management = crate::lifecycle::ManagementState::open(dir.path()).unwrap();
        management.authenticate();
        let epoch = management.auth_epoch;
        assert!(ensure_epoch(&mut management, epoch).is_ok());
        management.lock_interface();
        management.authenticate();
        assert!(ensure_epoch(&mut management, epoch).is_err());
        assert!(!management.persistent.service_paused);
    }
    fn fixture() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path()).unwrap();
        vault.create("synthetic-master-password").unwrap();
        vault.add_site(serde_json::from_value(json!({"alias":"e10-test","site_url":"https://e10.example","auth_type":"e10","secret":{"cookies":[]}})).unwrap()).unwrap();
        (dir, vault)
    }
    #[test]
    fn stale_login_cannot_save_after_pause_edit_or_deletion() {
        let (_dir, mut vault) = fixture();
        let generation = vault.generation();
        assert!(bound_site(&vault, "e10-test", "https://e10.example", Some(generation)).is_ok());
        assert!(bound_site(
            &vault,
            "e10-test",
            "https://other.example",
            Some(generation)
        )
        .is_err());
        vault
            .update_details("e10-test", json!({"notes":"changed"}))
            .unwrap();
        assert!(bound_site(&vault, "e10-test", "https://e10.example", Some(generation)).is_err());
        vault.lock();
        assert!(bound_site(&vault, "e10-test", "https://e10.example", None).is_err());
    }
}
