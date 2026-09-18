use crate::{
    lifecycle::{atomic_write, ManagementState},
    platform,
};
use pman_core::{
    ipc::{self, IpcRequest},
    Broker, BrokerResult, HttpRequest, Vault,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::{Duration, Instant},
};
use tauri::Emitter;

pub struct CoreState {
    pub vault: Vault,
    pub broker: Broker,
}
pub struct LoginBinding {
    pub alias: String,
    pub origin: String,
    pub label: String,
    pub generation: u64,
    pub auth_epoch: u64,
}
pub struct PendingE10 {
    pub alias: String,
    pub origin: String,
    pub flow: Option<pman_core::e10::E10AuthFlow>,
    pub generation: u64,
    pub auth_epoch: u64,
}
/// Provider-agnostic OAuth flow handle. Secrets never leave the flow.
pub enum PendingOAuthFlow {
    GitLab(pman_core::oauth::GitLabOAuthFlow),
    GitHub(pman_core::oauth::GitHubDeviceFlow),
}
impl PendingOAuthFlow {
    pub fn info(&self) -> pman_core::oauth::OAuthStart {
        match self {
            Self::GitLab(flow) => flow.info(),
            Self::GitHub(flow) => flow.info(),
        }
    }
    pub fn cancellation(&self) -> Arc<std::sync::atomic::AtomicBool> {
        match self {
            Self::GitLab(flow) => flow.cancellation(),
            Self::GitHub(flow) => flow.cancellation(),
        }
    }
    pub fn cancel(&self) {
        match self {
            Self::GitLab(flow) => flow.cancel(),
            Self::GitHub(flow) => flow.cancel(),
        }
    }
    pub fn complete(
        self,
        timeout: Duration,
    ) -> Result<pman_core::oauth::OAuthResult, pman_core::oauth::OAuthError> {
        match self {
            Self::GitLab(flow) => flow.complete(timeout),
            Self::GitHub(flow) => flow.complete(timeout),
        }
    }
}
pub struct PendingOAuth {
    pub alias: String,
    pub provider: String,
    pub flow: Option<PendingOAuthFlow>,
    pub generation: u64,
    pub auth_epoch: u64,
}
#[derive(Clone)]
pub struct Shared {
    pub core: Arc<Mutex<CoreState>>,
    pub management: Arc<Mutex<ManagementState>>,
    pub home: PathBuf,
    pub browser_logins: Arc<Mutex<HashMap<String, LoginBinding>>>,
    pub e10_flows: Arc<Mutex<HashMap<String, PendingE10>>>,
    pub e10_cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    pub oauth_flows: Arc<Mutex<HashMap<String, PendingOAuth>>>,
    /// Single-flight guard per alias while a token refresh is running.
    pub oauth_refreshing: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}
impl Shared {
    pub fn open() -> Result<Self, String> {
        Self::open_at(ipc::native_home())
    }
    pub fn open_at(home: PathBuf) -> Result<Self, String> {
        let vault = Vault::open(&home).map_err(|_| "无法打开本机保险库")?;
        let management = ManagementState::open(&home)?;
        let state = Self {
            core: Arc::new(Mutex::new(CoreState {
                vault,
                broker: Broker::new(),
            })),
            management: Arc::new(Mutex::new(management)),
            home,
            browser_logins: Default::default(),
            e10_flows: Default::default(),
            e10_cancellations: Default::default(),
            oauth_flows: Default::default(),
            oauth_refreshing: Default::default(),
        };
        let should_resume = state.management.lock().unwrap().should_resume();
        if should_resume {
            let path = state.home.join("service-key.bin");
            if path.exists() {
                let result = std::fs::read(path)
                    .map_err(|_| ())
                    .and_then(|v| ipc::unprotect(&v).map_err(|_| ()))
                    .and_then(|key| {
                        state
                            .core
                            .lock()
                            .unwrap()
                            .vault
                            .resume_with_key(&key)
                            .map_err(|_| ())
                    });
                if result.is_err() {
                    state.management.lock().unwrap().startup_error =
                        Some("自动恢复失败，请使用主密码恢复服务".into());
                }
            }
        }
        Ok(state)
    }
    pub fn require_management(&self) -> Result<(), String> {
        self.management
            .lock()
            .map_err(|_| "管理状态不可用")?
            .require_authenticated()
    }
    pub fn lock_interface(&self) {
        if let Ok(mut state) = self.management.lock() {
            state.lock_interface();
        }
        self.cancel_logins();
    }
    fn cancel_logins(&self) {
        if let Ok(cancellations) = self.e10_cancellations.lock() {
            for flag in cancellations.values() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        if let Ok(mut flows) = self.e10_flows.lock() {
            flows.clear();
        }
        if let Ok(mut logins) = self.browser_logins.lock() {
            logins.clear();
        }
        if let Ok(mut flows) = self.oauth_flows.lock() {
            for pending in flows.values() {
                pending.flow.as_ref().map(|flow| flow.cancel());
            }
            flows.clear();
        }
        if let Ok(mut refreshing) = self.oauth_refreshing.lock() {
            for flag in refreshing.values() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            refreshing.clear();
        }
    }
    pub fn save_resume_material(&self) -> Result<(), String> {
        let key = self
            .core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .export_resume_key()
            .map_err(|_| "服务尚未解锁")?;
        let wrapped = ipc::protect(&key).map_err(|_| "无法保存本机自动恢复材料")?;
        atomic_write(&self.home.join("service-key.bin"), &wrapped)
    }
    pub fn pause(&self) -> Result<(), String> {
        let mut management = self.management.lock().map_err(|_| "管理状态不可用")?;
        management.set_paused(true)?;
        management.lock_interface();
        self.core.lock().map_err(|_| "服务状态不可用")?.vault.lock();
        self.cancel_logins();
        Ok(())
    }
    pub fn resume_password(&self, password: &str) -> Result<(), String> {
        let mut management = self.management.lock().map_err(|_| "管理状态不可用")?;
        self.core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .unlock(password)
            .map_err(|e| e.to_string())?;
        if let Err(e) = self
            .save_resume_material()
            .and_then(|_| management.set_paused(false))
        {
            self.core.lock().unwrap().vault.lock();
            return Err(e);
        }
        management.authenticate();
        management.startup_error = None;
        Ok(())
    }
    pub fn unlock_protected(&self, resume: bool, epoch: Option<u64>) -> Result<(), String> {
        let bytes = std::fs::read(self.home.join("service-key.bin"))
            .map_err(|_| "本机恢复材料不存在，请使用主密码")?;
        let key = ipc::unprotect(&bytes).map_err(|_| "本机恢复材料不可用，请使用主密码")?;
        let mut management = self.management.lock().map_err(|_| "管理状态不可用")?;
        if epoch.is_some_and(|epoch| management.auth_epoch != epoch) {
            return Err("验证期间管理界面已锁定，请重新验证".into());
        }
        self.core
            .lock()
            .map_err(|_| "服务状态不可用")?
            .vault
            .resume_with_key(&key)
            .map_err(|_| "本机恢复材料已失效，请使用主密码")?;
        if resume {
            if let Err(e) = management.set_paused(false) {
                self.core.lock().unwrap().vault.lock();
                return Err(e);
            }
        }
        management.authenticate();
        management.startup_error = None;
        Ok(())
    }
    pub fn status(&self) -> Result<Value, String> {
        let management = self.management.lock().map_err(|_| "管理状态不可用")?;
        let core = self.core.lock().map_err(|_| "服务状态不可用")?;
        let running = core.vault.unlocked() && !management.persistent.service_paused;
        let pending = core
            .vault
            .list_approvals("pending")
            .map(|v| v.len())
            .unwrap_or(0)
            + core
                .vault
                .list_assistance(Some("pending"))
                .map(|v| v.len())
                .unwrap_or(0);
        Ok(
            json!({"home":self.home.display().to_string(),"initialized":core.vault.initialized().map_err(|e|e.to_string())?,"unlocked":core.vault.unlocked(),"management_locked":!management.authenticated,"service_running":running,"service_paused":management.persistent.service_paused,"pending_approvals":pending,"hello_available":management.hello_available,"ai_proxy":{"state":if running{"running"}else if management.persistent.service_paused{"paused"}else{"locked"},"address":ipc::pipe_name().unwrap_or_default(),"managed":true,"detail":management.startup_error.clone().unwrap_or_else(||if running{"已授权 AI 可持续调用；管理界面可单独锁定".into()}else if management.persistent.service_paused{"已主动暂停，重启不会自动恢复".into()}else{"请验证身份以启动服务".into()})}}),
        )
    }
    pub fn start_background(&self, app: tauri::AppHandle) {
        let transport = self.clone();
        let transport_app = app.clone();
        std::thread::spawn(move || {
            let callback = transport.clone();
            if ipc::serve(Arc::new(move |request| callback.dispatch(request))).is_err() {
                if let Ok(mut m) = transport.management.lock() {
                    m.startup_error =
                        Some("本机代理通道无法启动，请检查是否存在旧实例后重启 pman".into());
                    m.lock_interface();
                    if let Ok(mut core) = transport.core.lock() {
                        core.vault.lock();
                    }
                }
                let _ = transport_app.emit("service-changed", ());
            }
        });
        let background = self.clone();
        std::thread::spawn(move || {
            let available = platform::hello_available();
            if let Ok(mut m) = background.management.lock() {
                m.hello_available = available;
            }
            let _ = app.emit("service-changed", ());
            let enabled = background
                .management
                .lock()
                .unwrap()
                .persistent
                .settings
                .autostart;
            if let Ok(executable) = std::env::current_exe() {
                if let Err(e) = platform::set_autostart(enabled, &executable) {
                    background.management.lock().unwrap().startup_error = Some(e);
                }
            }
            if background
                .management
                .lock()
                .unwrap()
                .persistent
                .settings
                .legacy_http_enabled
            {
                crate::legacy_http::start(background.clone());
            }
            let mut last_pending = 0;
            let mut last_input = None;
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let input = platform::management_input(&app);
                let locked = background
                    .management
                    .lock()
                    .map(|mut m| {
                        if let Some(marker) = input {
                            if last_input != Some(marker) {
                                m.last_activity = Instant::now();
                                last_input = Some(marker);
                            }
                        }
                        m.idle_lock(platform::idle_seconds())
                    })
                    .unwrap_or(false);
                if locked {
                    background.cancel_logins();
                    close_login_windows(&app);
                    let _ = app.emit("management-locked", ());
                }
                let count = background
                    .core
                    .lock()
                    .map(|c| {
                        c.vault
                            .list_approvals("pending")
                            .map(|v| v.len())
                            .unwrap_or(0)
                            + c.vault
                                .list_assistance(Some("pending"))
                                .map(|v| v.len())
                                .unwrap_or(0)
                    })
                    .unwrap_or(0);
                if count != last_pending {
                    let _ = app.emit("approvals-changed", count);
                    if count > last_pending {
                        let _ = crate::native_dialogs::notify_open(
                            app.clone(),
                            "pman 授权请求",
                            "有新的请求需要你批准，已授权调用仍在继续。",
                        );
                    }
                    last_pending = count;
                }
            }
        });
    }
    pub fn http(
        &self,
        request: HttpRequest,
        harness: &str,
        expected_origin: Option<&str>,
    ) -> BrokerResult {
        self.http_as(request, harness, expected_origin, None)
    }
    fn http_as(
        &self,
        request: HttpRequest,
        harness: &str,
        expected_origin: Option<&str>,
        identity: Option<&IpcRequest>,
    ) -> BrokerResult {
        let prepared = {
            let management = match self.management.lock() {
                Ok(m) => m,
                Err(_) => return BrokerResult::failure("request_failed", "管理状态不可用"),
            };
            if management.persistent.service_paused {
                return BrokerResult::failure("vault_locked", "AI 授权服务已主动暂停");
            }
            let mut core = match self.core.lock() {
                Ok(c) => c,
                Err(_) => return BrokerResult::failure("request_failed", "服务状态不可用"),
            };
            if let Some(identity) = identity {
                if authenticate(&mut core.vault, identity).as_deref() != Ok(harness) {
                    return BrokerResult::failure("harness_invalid", "客户端身份已失效");
                }
            }
            if let Some(expected) = expected_origin {
                let alias = ipc::resolve_alias(&request.site);
                let actual = core
                    .vault
                    .list_sites()
                    .ok()
                    .and_then(|s| s.into_iter().find(|s| s.alias == alias))
                    .and_then(|s| tauri::Url::parse(&s.site_url).ok())
                    .map(|u| u.origin().ascii_serialization());
                if actual.as_deref() != Some(expected) {
                    return BrokerResult::failure("origin_mismatch", "连接环境与调用方要求不一致");
                }
            }
            let CoreState { vault, broker } = &mut *core;
            match broker.prepare(vault, request, Some(harness)) {
                Ok(p) => p,
                Err(result) => return result,
            }
        };
        let result = prepared.execute();
        let mut core = match self.core.lock() {
            Ok(c) => c,
            Err(_) => return BrokerResult::failure("request_failed", "服务状态不可用"),
        };
        let valid = identity.is_none_or(|identity| {
            authenticate(&mut core.vault, identity).as_deref() == Ok(harness)
        });
        let CoreState { vault, broker } = &mut *core;
        let result = broker.finish(vault, result);
        if valid {
            result
        } else {
            BrokerResult::failure(
                "harness_invalid",
                "客户端身份在请求期间失效，响应已停止交付；写操作不会自动重试",
            )
        }
    }
    pub fn dispatch(&self, request: IpcRequest) -> Value {
        let harness = match self.core.lock() {
            Ok(mut c) => match authenticate(&mut c.vault, &request) {
                Ok(h) => h,
                Err(_) => {
                    return ipc::result_error("harness_invalid", "客户端未配对、已过期或已撤销")
                }
            },
            Err(_) => return ipc::result_error("request_failed", "服务状态不可用"),
        };
        self.dispatch_authenticated(&request, &harness)
    }
    pub fn dispatch_authenticated(&self, request: &IpcRequest, harness: &str) -> Value {
        if matches!(request.operation.as_str(), "status" | "service_status") {
            let management = match self.management.lock() {
                Ok(m) => m,
                Err(_) => return ipc::result_error("request_failed", "管理状态不可用"),
            };
            let mut core = match self.core.lock() {
                Ok(c) => c,
                Err(_) => return ipc::result_error("request_failed", "服务状态不可用"),
            };
            if authenticate(&mut core.vault, request).as_deref() != Ok(harness) {
                return ipc::result_error("harness_invalid", "客户端身份已失效");
            }
            return ipc::result_ok(
                json!({"initialized":core.vault.initialized().unwrap_or(false),"unlocked":core.vault.unlocked(),"service_running":core.vault.unlocked()&&!management.persistent.service_paused,"service_paused":management.persistent.service_paused,"management_locked":!management.authenticated,"harness":harness}),
            );
        }
        if matches!(request.operation.as_str(), "http" | "call" | "run") {
            let value = request
                .args
                .get("request")
                .cloned()
                .unwrap_or_else(|| request.args.clone());
            let http = match serde_json::from_value::<HttpRequest>(value) {
                Ok(r) => r,
                Err(_) => return ipc::result_error("invalid_request", "请求结构无效"),
            };
            return serde_json::to_value(self.http_as(
                http,
                harness,
                request.args.get("expected_origin").and_then(Value::as_str),
                Some(request),
            ))
            .unwrap_or_else(|_| ipc::result_error("request_failed", "无法编码响应"));
        }
        if request.operation == "approval_wait" {
            let seconds = request
                .args
                .get("timeout_sec")
                .and_then(Value::as_u64)
                .unwrap_or(30)
                .min(60);
            let until = Instant::now() + Duration::from_secs(seconds);
            loop {
                let result = {
                    let mut core = match self.core.lock() {
                        Ok(c) => c,
                        Err(_) => return ipc::result_error("request_failed", "服务状态不可用"),
                    };
                    if authenticate(&mut core.vault, request).as_deref() != Ok(harness) {
                        return ipc::result_error("harness_invalid", "客户端身份已失效");
                    }
                    ipc::dispatch_metadata(&core.vault, request, harness)
                };
                if result.get("approval_status").and_then(Value::as_str) != Some("pending")
                    || Instant::now() >= until
                {
                    return result;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        let mut core = match self.core.lock() {
            Ok(c) => c,
            Err(_) => return ipc::result_error("request_failed", "服务状态不可用"),
        };
        if authenticate(&mut core.vault, request).as_deref() != Ok(harness) {
            return ipc::result_error("harness_invalid", "客户端身份已失效");
        }
        if let Some(response) = ipc::dispatch_assistance(&mut core.vault, request, harness) {
            return response;
        }
        ipc::dispatch_metadata(&core.vault, request, harness)
    }
}

pub fn close_login_windows(app: &tauri::AppHandle) {
    use tauri::Manager;
    for (label, window) in app.webview_windows() {
        if label != "main" {
            let _ = window.close();
        }
    }
}

fn authenticate(vault: &mut Vault, request: &IpcRequest) -> Result<String, String> {
    if request.client_id == "__legacy__" {
        vault.authenticate_legacy_token(&request.proof)
    } else {
        vault.authenticate_client(&request.client_id, &request.proof)
    }
    .map_err(|_| "harness_invalid".into())
}

pub fn ensure_main(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err("管理命令仅允许主窗口调用".into());
    }
    let url = window.url().map_err(|_| "无法验证管理窗口")?;
    let bundled =
        matches!(url.scheme(), "tauri" | "asset") || url.host_str() == Some("tauri.localhost");
    let dev = cfg!(debug_assertions)
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
        && url.port() == Some(1420);
    if bundled || dev {
        Ok(())
    } else {
        Err("不受信任的管理窗口来源".into())
    }
}
