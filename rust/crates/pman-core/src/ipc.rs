//! Current-user native broker transport. Only the desktop creates pairings.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
};
use zeroize::Zeroizing;

pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
pub struct IpcRequest {
    pub client_id: String,
    pub proof: String,
    pub operation: String,
    #[serde(default)]
    pub args: Value,
}
impl Drop for IpcRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.proof.zeroize();
    }
}
pub type Handler = Arc<dyn Fn(IpcRequest) -> Value + Send + Sync + 'static>;

pub fn native_home() -> PathBuf {
    if let Some(home) = std::env::var_os("PM_NATIVE_HOME") {
        return PathBuf::from(home);
    }
    PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_else(|| ".".into())).join("pman")
}
pub fn app_home() -> PathBuf {
    native_home()
}
fn invalid() -> std::io::Error {
    std::io::Error::other("Native broker identity or transport unavailable")
}

/// Returns only a one-way verifier. The capability is written protected, never printed.
pub fn create_pairing(client_id: &str) -> std::io::Result<String> {
    if !crate::workspace::valid_client_id(client_id) {
        return Err(invalid());
    }
    use rand::RngCore;
    let mut random = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(random.as_mut());
    let proof = Zeroizing::new(hex::encode(random.as_ref()));
    let protected = protect(proof.as_bytes())?;
    let dir = native_home().join("clients");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{client_id}.cap"));
    let temp = dir.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&temp, protected)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    std::fs::rename(temp, path)?;
    Ok(hex::encode(Sha256::digest(proof.as_bytes())))
}
pub fn remove_pairing(client_id: &str) -> std::io::Result<()> {
    if !crate::workspace::valid_client_id(client_id) {
        return Err(invalid());
    }
    let path = native_home()
        .join("clients")
        .join(format!("{client_id}.cap"));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn call(client_id: &str, operation: &str, args: Value) -> std::io::Result<Value> {
    if !crate::workspace::valid_client_id(client_id) {
        return Err(invalid());
    }
    let protected = std::fs::read(
        native_home()
            .join("clients")
            .join(format!("{client_id}.cap")),
    )
    .map_err(|_| invalid())?;
    let proof = unprotect(&protected)?;
    let proof = String::from_utf8(proof.to_vec()).map_err(|_| invalid())?;
    send(IpcRequest {
        client_id: client_id.into(),
        proof,
        operation: operation.into(),
        args,
    })
}

pub fn result_error(code: &str, message: &str) -> Value {
    json!({"protocol":"pman","protocol_version":2,"ok":false,"error_code":code,"error":message})
}
pub fn result_ok(fields: Value) -> Value {
    let mut result = json!({"protocol":"pman","protocol_version":2,"ok":true,"error_code":"ok"});
    if let Some(fields) = fields.as_object() {
        for (k, v) in fields {
            result[k] = v.clone();
        }
    }
    result
}
pub fn alias_ref(alias: &str) -> String {
    format!(
        "pman-alias-utf8:{}",
        URL_SAFE_NO_PAD.encode(alias.as_bytes())
    )
}
pub fn resolve_alias(alias: &str) -> String {
    alias
        .strip_prefix("pman-alias-utf8:")
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| alias.into())
}

/// Read-only operations. Call only after authenticate_client succeeds. No administration is exposed.
pub fn dispatch_metadata(vault: &crate::Vault, request: &IpcRequest, harness: &str) -> Value {
    match request.operation.as_str() {
        "contract" | "ai-help" => contract(),
        // Identity/capability handshake with no business side effects. It
        // proves the pairing channel and reports granted aliases; it is NOT
        // evidence that an AI tool has made a real business call.
        "handshake" => {
            let connections: Vec<Value> = vault
                .list_sites()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| {
                    s.auth_type != "password"
                        && vault.details(&s.alias).is_ok_and(|d| d.ai_enabled)
                        && visible_to(vault, harness, &s.alias)
                })
                .map(|s| json!({"alias":s.alias,"alias_ref":alias_ref(&s.alias),"origin":s.site_url}))
                .collect();
            // This timestamp covers identity verification (including this
            // handshake); real business usage is audit-log evidence only.
            let identity_last_used = vault
                .list_clients()
                .ok()
                .and_then(|clients| {
                    clients
                        .iter()
                        .filter(|c| c.harness == harness)
                        .filter_map(|c| c.last_used_at.clone())
                        .max()
                });
            result_ok(
                json!({"handshake":"pman/2","harness":harness,"capabilities":["http","sites","resolve_scenario","approval"],"connections":connections,"identity_last_used_at":identity_last_used}),
            )
        }
        "status" => result_ok(
            json!({"service_running":vault.unlocked(),"service_paused":!vault.unlocked(),"management_authentication":"desktop_only"}),
        ),
        "sites" => match vault.list_sites() {
            Ok(sites) => {
                let sites: Vec<Value> = sites
                    .into_iter()
                    .filter(|s| {
                        s.auth_type != "password"
                            && vault.details(&s.alias).is_ok_and(|d| d.ai_enabled)
                            && visible_to(vault, harness, &s.alias)
                    })
                    .map(|s| {
                        let reference = alias_ref(&s.alias);
                        let mut v = serde_json::to_value(s).unwrap_or(json!({}));
                        v["alias_ref"] = reference.into();
                        v
                    })
                    .collect();
                result_ok(json!({"sites":sites}))
            }
            Err(_) => result_error("request_failed", "Cannot list connections"),
        },
        "credential_status" | "active_context" => {
            let alias = resolve_alias(
                request
                    .args
                    .get("site")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            match vault
                .list_sites()
                .ok()
                .and_then(|s| s.into_iter().find(|s| s.alias == alias))
            {
                Some(site) => {
                    let details = vault.details(&alias).unwrap_or_default();
                    if !details.ai_enabled
                        || site.auth_type == "password"
                        || !visible_to(vault, harness, &alias)
                    {
                        return result_error(
                            "policy_denied",
                            "Connection is outside this client's granted scope",
                        );
                    }
                    let status = if crate::vault::is_expired(site.expires_at.as_deref()) {
                        "expired"
                    } else {
                        site.status.as_str()
                    };
                    let context = json!({"site":site.alias,"alias":site.alias,"alias_ref":alias_ref(&alias),"origin":site.site_url,"auth_type":site.auth_type,"account_id":details.extra.get("account_id").cloned().unwrap_or_else(||details.account.clone().into()),"environment_id":details.extra.get("environment_id").cloned().unwrap_or_else(||details.environment.clone().into()),"account":details.account,"environment":details.environment,"checked_at":details.extra.get("checked_at"),"user_id":details.extra.get("user_id"),"tenant_key":details.extra.get("tenant_key").or(details.extra.get("tenant")),"agent_type":details.extra.get("agent_type"),"status":status,"expires_at":site.expires_at,"last_used_at":site.last_used_at});
                    result_ok(json!({"context":context,"credential":context}))
                }
                None => result_error("unknown_site", "Unknown connection"),
            }
        }
        "resolve_scenario" => {
            let intent = request
                .args
                .get("intent")
                .and_then(Value::as_str)
                .unwrap_or("");
            let context = request
                .args
                .get("context")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let context =
                match serde_json::from_value::<std::collections::BTreeMap<String, String>>(context)
                {
                    Ok(context) => context,
                    Err(_) => {
                        return result_error(
                            "invalid_request",
                            "Scenario context must contain string values",
                        )
                    }
                };
            match vault.resolve_scenario(harness, intent, &context) {
                Ok(mut matches) if matches.len() == 1 => {
                    let mut matched =
                        serde_json::to_value(matches.remove(0)).unwrap_or_else(|_| json!({}));
                    if let Some(site) = matched.get("site").and_then(Value::as_str) {
                        matched["alias_ref"] = alias_ref(site).into();
                    }
                    result_ok(json!({"status":"resolved","match":matched}))
                }
                Ok(matches) if matches.is_empty() => result_error(
                    "scenario_not_found",
                    "No configured scenario matches this intent and context",
                ),
                Ok(matches) => {
                    let candidates = matches
                        .into_iter()
                        .map(|matched| {
                            json!({
                                "intent":matched.intent,
                                "capability":matched.capability,
                                "environment":matched.environment,
                                "services":matched.services,
                                "selectors":matched.selectors
                            })
                        })
                        .collect::<Vec<_>>();
                    let mut result = result_error(
                        "scenario_ambiguous",
                        "Multiple connections match; provide more context instead of choosing an account",
                    );
                    result["status"] = "ambiguous".into();
                    result["matches"] = candidates.into();
                    result
                }
                Err(_) => result_error("invalid_request", "Scenario query is invalid"),
            }
        }
        "approval_wait" | "request_status" => {
            let id = request
                .args
                .get("req_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            match vault.get_approval(id) {
                Ok(Some(a)) if a.harness == harness => result_ok(
                    json!({"req_id":a.id,"status":a.status,"approval_status":a.status,"consumed":a.consumed_at.is_some()}),
                ),
                _ => result_error("invalid_request", "Unknown request"),
            }
        }
        _ => result_error(
            "invalid_request",
            "Unsupported operation; manage credentials and approvals in the desktop application",
        ),
    }
}

pub(crate) fn visible_to(vault: &crate::Vault, harness: &str, alias: &str) -> bool {
    vault
        .get_policy(harness)
        .ok()
        .and_then(|v| crate::Policy::from_json(&v).ok())
        .is_some_and(|p| {
            p.default_action == crate::DefaultAction::Allow
                || p.allow
                    .iter()
                    .any(|r| r.site == alias && !crate::vault::is_expired(r.expires_at.as_deref()))
        })
}

/// Human-assistance inbox operations. The caller must authenticate the identity under the same vault lock.
pub fn dispatch_assistance(
    vault: &mut crate::Vault,
    request: &IpcRequest,
    harness: &str,
) -> Option<Value> {
    match request.operation.as_str() {
        "request_login" | "request_access" => {
            let site = request
                .args
                .get("site")
                .and_then(Value::as_str)
                .unwrap_or("");
            let reason = request
                .args
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("");
            let kind = if request.operation == "request_login" {
                "login"
            } else {
                "access"
            };
            let scope = if kind == "access" {
                match request
                    .args
                    .get("requested_scope")
                    .or_else(|| request.args.get("scope"))
                    .cloned()
                    .and_then(|v| serde_json::from_value::<crate::AssistanceScope>(v).ok())
                {
                    Some(scope) => Some(scope),
                    None => return Some(result_error(
                        "invalid_request",
                        "requested_scope must contain method, path and operation (query or write)",
                    )),
                }
            } else {
                None
            };
            Some(match vault.request_assistance(&request.client_id,harness,kind,site,scope,reason){
                Ok(assistance)=>result_ok(json!({"req_id":assistance.id,"status":assistance.status,"assistance_request":assistance,"message":"Request queued for a human. This does not change permissions or perform login."})),
                Err(crate::VaultError::Locked)=>result_error("vault_locked","Resume the authorization service in pman desktop before requesting assistance"),
                Err(_)=>result_error("policy_denied","Assistance request is invalid or outside this client's available connection scope"),
            })
        }
        "request_status" => {
            let id = request
                .args
                .get("req_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            match vault.assistance_status(id, &request.client_id, harness) {
                Ok(assistance) => Some(result_ok(
                    json!({"req_id":assistance.id,"status":assistance.status,"assistance_request":assistance}),
                )),
                Err(_) => None,
            }
        }
        _ => None,
    }
}

pub fn contract() -> Value {
    result_ok(
        json!({"contract":"pman-ai/2","summary":"Local credential broker. Resolve configured business scenarios and call aliases; never read passwords, cookies, tokens or vault files. Only a human may approve or resume service.","operations":["contract","handshake","sites","status","resolve_scenario","active_context","credential_status","http","approval_wait","request_status","request_access","request_login","browser_open","browser_summary","browser_click","browser_fill","browser_wait","browser_close"],"scenario_resolution":"resolve_scenario returns exactly one configured connection and business capability, or fails closed when context is missing or ambiguous.","approval":"pending_approval requires a human decision in pman desktop. The human may approve once or persist the exact client, connection, method, path and optional business capability; retry after the decision.","service_lifecycle":"Windows screen lock and management lock do not interrupt granted AI access. Explicit pause persists until the user resumes.","identity":"Client identity proof is DPAPI-protected. Client names do not confer permission."}),
    )
}

fn read_frame(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut size = [0u8; 4];
    reader.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    if size > MAX_MESSAGE {
        return Err(invalid());
    }
    let mut body = vec![0u8; size];
    reader.read_exact(&mut body)?;
    Ok(body)
}
fn write_frame(writer: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    if body.len() > MAX_MESSAGE {
        return Err(invalid());
    }
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle},
        ptr::{null, null_mut},
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, Cryptography::*, *},
        Storage::FileSystem::*,
        System::{Pipes::*, Threading::*},
    };
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    pub fn protect(value: &[u8]) -> std::io::Result<Vec<u8>> {
        unsafe {
            let source = CRYPT_INTEGER_BLOB {
                cbData: value.len() as u32,
                pbData: value.as_ptr() as *mut u8,
            };
            let mut output: CRYPT_INTEGER_BLOB = std::mem::zeroed();
            if CryptProtectData(
                &source,
                null(),
                null(),
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            ) == 0
            {
                return Err(invalid());
            }
            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as *mut _);
            Ok(result)
        }
    }
    pub fn unprotect(value: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        unsafe {
            let source = CRYPT_INTEGER_BLOB {
                cbData: value.len() as u32,
                pbData: value.as_ptr() as *mut u8,
            };
            let mut output: CRYPT_INTEGER_BLOB = std::mem::zeroed();
            if CryptUnprotectData(
                &source,
                null_mut(),
                null(),
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            ) == 0
            {
                return Err(invalid());
            }
            let result = Zeroizing::new(
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec(),
            );
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            LocalFree(output.pbData as *mut _);
            Ok(result)
        }
    }
    fn user_sid() -> std::io::Result<String> {
        unsafe {
            let mut token = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(invalid());
            }
            let mut length = 0;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
            let mut buffer = vec![0u8; length as usize];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut _,
                length,
                &mut length,
            );
            CloseHandle(token);
            if ok == 0 {
                return Err(invalid());
            }
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut sid = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
                return Err(invalid());
            }
            let mut n = 0;
            while *sid.add(n) != 0 {
                n += 1
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, n));
            LocalFree(sid as *mut _);
            Ok(value)
        }
    }
    pub fn pipe_name() -> std::io::Result<String> {
        let home = std::path::absolute(native_home())?;
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        let raw = home.to_string_lossy().replace('/', "\\");
        let normalized = raw.strip_prefix("\\\\?\\").unwrap_or(&raw).to_lowercase();
        let id = hex::encode(Sha256::digest(
            format!("{}|{}", user_sid()?, normalized).as_bytes(),
        ));
        Ok(format!("\\\\.\\pipe\\pman-{}", &id[..32]))
    }
    pub fn send(request: IpcRequest) -> std::io::Result<Value> {
        let pipe = pipe_name()?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe)?;
        let mut stream = DeadlinePipe::new(file, Duration::from_secs(70))?;
        let body = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| invalid())?);
        write_frame(&mut stream, &body)?;
        let response = read_frame(&mut stream)?;
        // Keep the server pipe open until the complete response has been consumed.
        stream.write_all(&[1])?;
        serde_json::from_slice(&response).map_err(|_| invalid())
    }
    struct DeadlinePipe {
        file: std::fs::File,
        deadline: Instant,
    }
    impl DeadlinePipe {
        fn new(file: std::fs::File, timeout: Duration) -> std::io::Result<Self> {
            unsafe {
                let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
                if SetNamedPipeHandleState(file.as_raw_handle(), &mode, null(), null()) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(Self {
                file,
                deadline: Instant::now() + timeout,
            })
        }
        fn wait(&self) -> std::io::Result<()> {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Broker transport timed out; an operation already sent is not retried",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
            Ok(())
        }
    }
    fn would_wait(error: &std::io::Error) -> bool {
        matches!(error.raw_os_error(), Some(232 | 231 | 536))
    }
    impl Read for DeadlinePipe {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            loop {
                match self.file.read(buffer) {
                    Ok(0) if !buffer.is_empty() => self.wait()?,
                    Err(e) if would_wait(&e) => self.wait()?,
                    result => return result,
                }
            }
        }
    }
    impl Write for DeadlinePipe {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            loop {
                match self.file.write(&buffer[..buffer.len().min(16384)]) {
                    Ok(0) if !buffer.is_empty() => self.wait()?,
                    Err(e) if would_wait(&e) => self.wait()?,
                    result => return result,
                }
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }
    struct WorkerGuard(Arc<AtomicUsize>);
    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    pub fn serve(handler: Handler) -> std::io::Result<()> {
        unsafe {
            let sddl = wide(&format!("D:P(A;;GA;;;{})", user_sid()?));
            let mut descriptor = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(invalid());
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let name = wide(&pipe_name()?);
            let mut first = true;
            let workers = Arc::new(AtomicUsize::new(0));
            loop {
                let flags = PIPE_ACCESS_DUPLEX
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    };
                let pipe = CreateNamedPipeW(
                    name.as_ptr(),
                    flags,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    &attrs,
                );
                if pipe == INVALID_HANDLE_VALUE {
                    LocalFree(descriptor);
                    return Err(std::io::Error::last_os_error());
                }
                first = false;
                if ConnectNamedPipe(pipe, null_mut()) == 0 && GetLastError() != ERROR_PIPE_CONNECTED
                {
                    CloseHandle(pipe);
                    continue;
                }
                if workers.load(Ordering::Acquire) >= 16 {
                    CloseHandle(pipe);
                    continue;
                }
                workers.fetch_add(1, Ordering::AcqRel);
                let guard = WorkerGuard(workers.clone());
                let callback = handler.clone();
                let raw = pipe as usize;
                std::thread::spawn(move || {
                    let _guard = guard;
                    let file = std::fs::File::from_raw_handle(raw as *mut _);
                    let Ok(mut stream) = DeadlinePipe::new(file, Duration::from_secs(5)) else {
                        return;
                    };
                    let response =
                        match read_frame(&mut stream)
                            .map(Zeroizing::new)
                            .and_then(|data| {
                                serde_json::from_slice::<IpcRequest>(&data).map_err(|_| invalid())
                            }) {
                            Ok(request) => callback(request),
                            Err(_) => result_error("invalid_request", "Invalid broker request"),
                        };
                    stream.deadline = Instant::now() + Duration::from_secs(5);
                    if let Ok(data) = serde_json::to_vec(&response) {
                        if write_frame(&mut stream, &data).is_ok() {
                            let mut acknowledgement = [0u8; 1];
                            let _ = stream.read_exact(&mut acknowledgement);
                        }
                    }
                });
            }
        }
    }
}
#[cfg(windows)]
use windows::send;
#[cfg(windows)]
pub use windows::{pipe_name, protect, serve, unprotect};
#[cfg(not(windows))]
pub fn protect(_: &[u8]) -> std::io::Result<Vec<u8>> {
    Err(invalid())
}
#[cfg(not(windows))]
pub fn unprotect(_: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
    Err(invalid())
}
#[cfg(not(windows))]
pub fn pipe_name() -> std::io::Result<String> {
    Err(invalid())
}
#[cfg(not(windows))]
pub fn serve(_: Handler) -> std::io::Result<()> {
    Err(invalid())
}
#[cfg(not(windows))]
fn send(_: IpcRequest) -> std::io::Result<Value> {
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alias_roundtrip_handles_chinese() {
        let alias = "E10 开发环境";
        assert_eq!(resolve_alias(&alias_ref(alias)), alias);
    }
    #[test]
    fn oversized_frame_rejected_before_allocation() {
        let bytes = ((MAX_MESSAGE + 1) as u32).to_le_bytes();
        assert!(read_frame(&mut bytes.as_slice()).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip() {
        let bytes = b"synthetic test only";
        let protected = protect(bytes).unwrap();
        assert_ne!(protected, bytes);
        assert_eq!(unprotect(&protected).unwrap().as_slice(), bytes);
    }
    #[cfg(windows)]
    #[test]
    fn native_pipe_authenticates_protected_pairing_and_rejects_forgery() {
        let temp = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("PM_NATIVE_HOME");
        std::env::set_var("PM_NATIVE_HOME", temp.path());
        let mut vault = crate::Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        let verifier = create_pairing("test-client").unwrap();
        vault
            .pair_client("test-harness", "test-client", &verifier)
            .unwrap();
        let vault = Arc::new(std::sync::Mutex::new(vault));
        let state = vault.clone();
        std::thread::spawn(move || {
            let _ = serve(Arc::new(move |request| {
                let mut vault = state.lock().unwrap();
                match vault.authenticate_client(&request.client_id, &request.proof) {
                    Ok(harness) => {
                        if request.operation == "large_test" {
                            result_ok(json!({"body":"x".repeat(1024*1024)}))
                        } else {
                            dispatch_metadata(&vault, &request, &harness)
                        }
                    }
                    Err(_) => result_error("harness_invalid", "Invalid client"),
                }
            }));
        });
        let mut response = None;
        for _ in 0..50 {
            match call("test-client", "status", json!({})) {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("synthetic pipe test transport failed: {error}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(response.unwrap()["service_running"], true);
        assert_eq!(
            call("test-client", "large_test", json!({})).unwrap()["body"]
                .as_str()
                .unwrap()
                .len(),
            1024 * 1024
        );
        let forged = send(IpcRequest {
            client_id: "test-client".into(),
            proof: "b".repeat(64),
            operation: "status".into(),
            args: json!({}),
        })
        .unwrap();
        assert_eq!(forged["error_code"], "harness_invalid");
        vault.lock().unwrap().revoke_client("test-client").unwrap();
        assert_eq!(
            call("test-client", "status", json!({})).unwrap()["error_code"],
            "harness_invalid"
        );
        if let Some(value) = previous {
            std::env::set_var("PM_NATIVE_HOME", value)
        } else {
            std::env::remove_var("PM_NATIVE_HOME")
        }
    }
}
