//! OAuth login commands (GitLab PKCE / GitHub device flow). Same isolation
//! rules as the E10 flow: epoch + generation binding, cancel-safe, and tokens
//! never cross the management UI boundary.
use crate::service::{PendingOAuth, PendingOAuthFlow, Shared};
use pman_core::oauth::{OAuthError, OAuthStart};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};

use crate::login::{begin_management, ensure_epoch};
use crate::service::ensure_main as login_ensure_main;

fn oauth_error(error: OAuthError) -> String {
    format!("{}: {}", error.code(), error)
}

/// OAuth is only offered where the provider flow is real; anything else keeps
/// the Token path. Provider detection matches the read-only check rules.
fn oauth_provider_for(site: &pman_core::SiteSummary, details: &pman_core::ConnectionDetails) -> Option<String> {
    if site.auth_type == "password" || site.site_url.is_empty() {
        return None;
    }
    match details.provider.as_deref() {
        Some("github") => return Some("github".into()),
        Some("gitlab") => return Some("gitlab".into()),
        Some(_) => return None,
        None => {}
    }
    let host = tauri::Url::parse(&site.site_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    match host.as_str() {
        "api.github.com" => Some("github".into()),
        "gitlab.com" | "www.gitlab.com" => Some("gitlab".into()),
        host if host.ends_with(".gitlab.com") => Some("gitlab".into()),
        _ => None,
    }
}

#[tauri::command]
pub async fn oauth_begin(
    _app: AppHandle,
    alias: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<OAuthStart, String> {
    login_ensure_main(&window)?;
    let auth_epoch = begin_management(&state)?;
    let (site, details, generation) = {
        let core = state.core.lock().map_err(|_| "服务状态不可用")?;
        let site = core
            .vault
            .list_sites()
            .map_err(|_| "无法读取连接")?
            .into_iter()
            .find(|site| site.alias == alias)
            .ok_or("连接不存在")?;
        let details = core.vault.details(&alias).map_err(|_| "无法读取连接")?;
        (site, details, core.vault.generation())
    };
    let provider = oauth_provider_for(&site, &details).ok_or(
        "oauth_unsupported: 此服务没有已确认的免密 OAuth 流程，请使用 Token 接入",
    )?;
    let client_id = details
        .oauth_client_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or(
            "oauth_unconfigured: 请先在此连接中保存 OAuth 应用 client_id（无需 client secret）",
        )?;
    let scope = details
        .oauth_scope
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if provider == "github" {
                "read:user".into()
            } else {
                "read_user".into()
            }
        });
    {
        let flows = state.oauth_flows.lock().map_err(|_| "登录状态不可用")?;
        if flows.values().any(|pending| pending.alias == alias) {
            return Err("此连接已有 OAuth 登录正在进行，请先完成或取消".into());
        }
    }
    let flow = if provider == "gitlab" {
        let target = pman_core::oauth::normalize_origin(&site.site_url).map_err(oauth_error)?;
        PendingOAuthFlow::GitLab(
            pman_core::oauth::GitLabOAuthFlow::begin(&target, client_id.trim(), &scope)
                .map_err(oauth_error)?,
        )
    } else {
        PendingOAuthFlow::GitHub(
            pman_core::oauth::GitHubDeviceFlow::begin(client_id.trim(), &scope)
                .map_err(oauth_error)?,
        )
    };
    let info = flow.info();
    {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        let mut flows = state.oauth_flows.lock().map_err(|_| "登录状态不可用")?;
        flows.insert(
            info.session_id.clone(),
            PendingOAuth {
                alias: alias.clone(),
                provider: info.provider.clone(),
                flow: Some(flow),
                generation,
                auth_epoch,
            },
        );
    }
    if crate::native_dialogs::open_external_url(&info.url).is_err() {
        if let Some(pending) = state
            .oauth_flows
            .lock()
            .map_err(|_| "登录状态不可用")?
            .remove(&info.session_id)
        {
            if let Some(flow) = pending.flow {
                flow.cancel();
            }
        }
        return Err("无法打开系统浏览器".into());
    }
    Ok(info)
}

#[tauri::command]
pub async fn oauth_complete(
    app: AppHandle,
    session_id: String,
    alias: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    login_ensure_main(&window)?;
    let current_epoch = begin_management(&state)?;
    let (provider, generation, auth_epoch, flow) = {
        let mut flows = state.oauth_flows.lock().map_err(|_| "登录状态不可用")?;
        if flows
            .get(&session_id)
            .is_none_or(|pending| pending.alias != alias || pending.auth_epoch != current_epoch)
        {
            return Err("登录事务不存在或与连接不匹配".into());
        }
        let pending = flows.get_mut(&session_id).ok_or("登录事务已结束")?;
        (
            pending.provider.clone(),
            pending.generation,
            pending.auth_epoch,
            pending.flow.take().ok_or("该登录事务已在处理中")?,
        )
    };
    let outcome =
        tauri::async_runtime::spawn_blocking(move || flow.complete(std::time::Duration::from_secs(600)))
            .await
            .map_err(|_| "登录检查失败")?;
    state
        .oauth_flows
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&session_id);
    login_ensure_main(&window)?;
    let account = {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        ensure_epoch(&mut management, auth_epoch)?;
        if management.persistent.service_paused {
            return Err("service_paused: AI 服务已暂停".into());
        }
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        if generation != core.vault.generation() {
            return Err("stale_login: 登录期间连接或授权发生变化，请重新开始".into());
        }
        let result = outcome.map_err(oauth_error)?;
        let account = result.account.clone();
        core.vault
            .finish_oauth_login(&alias, &provider, &result)
            .map_err(|e| e.to_string())?;
        account
    };
    let _ = app.emit("connections-changed", ());
    Ok(json!({
        "status": "connected",
        "provider": provider,
        "account": account,
        "message": "OAuth 登录成功，账号身份已验证",
    }))
}

#[tauri::command]
pub fn oauth_cancel(
    session_id: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<(), String> {
    login_ensure_main(&window)?;
    state.require_management()?;
    if let Some(pending) = state
        .oauth_flows
        .lock()
        .map_err(|_| "登录状态不可用")?
        .remove(&session_id)
    {
        if let Some(flow) = pending.flow {
            flow.cancel();
        }
    }
    Ok(())
}

#[tauri::command]
pub fn oauth_status(
    session_id: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    login_ensure_main(&window)?;
    state.require_management()?;
    let flows = state.oauth_flows.lock().map_err(|_| "登录状态不可用")?;
    match flows.get(&session_id) {
        Some(pending) => {
            let info = pending.flow.as_ref().map(|flow| flow.info());
            Ok(json!({
                "exists": true,
                "provider": pending.provider,
                "expires_at": info.as_ref().map(|info| info.expires_at.clone()),
                "waiting": info.is_some(),
            }))
        }
        None => Ok(json!({"exists": false})),
    }
}

/// Single-flight token refresh. A failed refresh never deletes stored tokens
/// and never blocks a later manual retry.
#[tauri::command]
pub async fn oauth_refresh(
    alias: String,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Value, String> {
    login_ensure_main(&window)?;
    let auth_epoch = begin_management(&state)?;
    let flag = {
        let mut refreshing = state
            .oauth_refreshing
            .lock()
            .map_err(|_| "服务状态不可用")?;
        if refreshing.contains_key(&alias) {
            return Err("此连接的令牌刷新已在进行中".into());
        }
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        refreshing.insert(alias.clone(), flag.clone());
        flag
    };
    let shared = state.inner().clone();
    let task_alias = alias.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("刷新已取消".into());
        }
        let mut core = shared.core.lock().map_err(|_| "服务状态不可用")?;
        core.vault
            .refresh_connection_tokens(&task_alias, None)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "刷新执行失败")?;
    state
        .oauth_refreshing
        .lock()
        .map_err(|_| "服务状态不可用")?
        .remove(&alias);
    login_ensure_main(&window)?;
    let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
    ensure_epoch(&mut management, auth_epoch)?;
    drop(management);
    let message = outcome?;
    {
        let mut core = state.core.lock().map_err(|_| "服务状态不可用")?;
        core.vault
            .finish_e10_evidence(&alias, "verified", None, "OAuth 令牌已刷新", None)
            .map_err(|e| e.to_string())?;
    }
    let _ = window.app_handle().emit("connections-changed", ());
    Ok(json!({"status": "refreshed", "message": message}))
}
