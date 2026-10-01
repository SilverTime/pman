//! Connection login provider. Only `ConnectionAccountMetadata` may cross the management UI boundary.
//! Codes, cookies and access tokens stay inside the broker; errors never contain URLs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

/// Declarative authentication, interpreted only inside the native broker.
/// Templates can reference ${code}, ${redirect_uri}, ${verifier}, ${origin},
/// ${var:name}, or ${cookie:name}. No scripts or external commands are executed.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub authorization: Option<Authorization>,
    pub exchange: Vec<Step>,
    pub refresh: Vec<Step>,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub check: Option<IdentityCheck>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub path: String,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub callback_port: u16,
    #[serde(default = "yes")]
    pub pkce: bool,
}
fn yes() -> bool {
    true
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Step {
    pub path: String,
    pub method: String,
    pub query: BTreeMap<String, String>,
    pub form: BTreeMap<String, String>,
    pub json: Option<Value>,
    pub headers: BTreeMap<String, String>,
    /// Variable name -> JSON pointer, header:name, or cookie:name.
    pub extract: BTreeMap<String, Vec<String>>,
    pub optional_extract: BTreeMap<String, Vec<String>>,
    /// JSON pointer containing a Cookie header supplied by the service.
    pub cookie_header: Option<String>,
    /// Skip this step when all named variables already exist.
    pub skip_if_present: Vec<String>,
    pub expect: BTreeMap<String, Value>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityCheck {
    pub request: Step,
    pub user_id: Vec<String>,
    pub user_name: Vec<String>,
    pub tenant_id: Vec<String>,
    pub tenant_name: Vec<String>,
}

impl Profile {
    pub fn validate(&self) -> Result<(), ConnectionError> {
        if self.exchange.len() > 8 || self.refresh.len() > 8 {
            return Err(ConnectionError::InvalidConfiguration);
        }
        if let Some(auth) = &self.authorization {
            if !matches!(auth.kind.as_str(), "" | "code" | "device") {
                return Err(ConnectionError::InvalidConfiguration);
            }
            if let Some(origin) = &auth.origin {
                normalize_origin(origin)?;
            }
            endpoint("https://service.invalid", &auth.path)?;
            if auth.params.keys().any(|k| {
                matches!(
                    k.as_str(),
                    "state"
                        | "redirect_uri"
                        | "response_type"
                        | "code_challenge"
                        | "code_challenge_method"
                )
            }) {
                return Err(ConnectionError::InvalidConfiguration);
            }
            if self.exchange.is_empty() {
                return Err(ConnectionError::InvalidConfiguration);
            }
        }
        for step in self
            .exchange
            .iter()
            .chain(&self.refresh)
            .chain(self.check.iter().map(|c| &c.request))
        {
            endpoint("https://service.invalid", &step.path)?;
            if !matches!(step.method.as_str(), "" | "GET" | "POST")
                || (step.json.is_some() && !step.form.is_empty())
            {
                return Err(ConnectionError::InvalidConfiguration);
            }
            for key in step.headers.keys() {
                validate_header(key)?;
            }
        }
        for key in self.headers.keys() {
            validate_header(key)?;
        }
        if self.check.as_ref().is_some_and(|c| c.user_id.is_empty()) {
            return Err(ConnectionError::InvalidConfiguration);
        }
        Ok(())
    }
}
pub fn profile(secret: &Value) -> Result<Profile, ConnectionError> {
    let value = secret.get("auth_profile").cloned().unwrap_or(json!({}));
    let profile: Profile =
        serde_json::from_value(value).map_err(|_| ConnectionError::InvalidConfiguration)?;
    profile.validate()?;
    Ok(profile)
}
fn endpoint(origin: &str, path: &str) -> Result<Url, ConnectionError> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['?', '#', '\\']) {
        return Err(ConnectionError::InvalidConfiguration);
    }
    if path.split('/').any(|s| s == ".." || s == ".") {
        return Err(ConnectionError::InvalidConfiguration);
    }
    let url = crate::http_proxy::build_url(origin, path, None)
        .map_err(|_| ConnectionError::InvalidConfiguration)?;
    let target = Url::parse(&url).map_err(|_| ConnectionError::InvalidOrigin)?;
    if target.origin().ascii_serialization() != normalize_origin(origin)? {
        return Err(ConnectionError::InvalidOrigin);
    }
    Ok(target)
}
fn validate_header(name: &str) -> Result<(), ConnectionError> {
    reqwest::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| ConnectionError::InvalidConfiguration)?;
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "connection" | "transfer-encoding" | "proxy-authorization"
    ) {
        return Err(ConnectionError::InvalidConfiguration);
    }
    Ok(())
}

const AUTH_LIFETIME_SECONDS: i64 = 600;
const JSON_LIMIT: u64 = 512 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConnectionError {
    #[error("authorization is pending")]
    Pending,
    #[error("authorization polling must slow down")]
    SlowDown,
    #[error("Connection origin must be an HTTPS origin (HTTP is allowed only on loopback)")]
    InvalidOrigin,
    #[error("invalid connection configuration")]
    InvalidConfiguration,
    #[error("Connection callback state is missing or does not match; use isolated website login if this environment does not return state")]
    InvalidState,
    #[error("Connection login was cancelled")]
    Cancelled,
    #[error("Connection login timed out")]
    Timeout,
    #[error("Connection authentication has expired; sign in again")]
    Expired,
    #[error("Connection permission was denied")]
    Forbidden,
    #[error("Connection network request failed")]
    Network,
    #[error("Connection returned an invalid authentication response")]
    InvalidResponse,
    #[error("Connection account does not match the account bound to this connection")]
    AccountMismatch,
}

impl ConnectionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Pending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::InvalidOrigin => "invalid_origin",
            Self::InvalidConfiguration => "invalid_request",
            Self::InvalidState => "invalid_state",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Expired => "expired",
            Self::Forbidden => "forbidden",
            Self::Network => "network_error",
            Self::InvalidResponse => "invalid_response",
            Self::AccountMismatch => "account_mismatch",
        }
    }
}

#[derive(Clone, Serialize)]
pub struct ConnectionAuthStart {
    pub session_id: String,
    pub authorize_url: String,
    pub expires_at: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConnectionAccountMetadata {
    pub environment_id: String,
    pub account_id: String,
    pub origin: String,
    pub user_id: String,
    pub tenant_key: String,
    pub user_name: String,
    pub tenant_name: String,
    pub version: String,
    pub status: String,
    pub checked_at: String,
}

// Intentionally neither Debug nor Serialize: callers must persist secret separately.
pub struct ConnectionLoginResult {
    pub metadata: ConnectionAccountMetadata,
    pub secret: Value,
}

pub struct ConnectionAuthFlow {
    info: ConnectionAuthStart,
    listener: Option<TcpListener>,
    state: Zeroizing<String>,
    verifier: Option<Zeroizing<String>>,
    redirect_uri: String,
    profile: Profile,
    started: Instant,
    cancelled: Arc<AtomicBool>,
    device: Option<(Zeroizing<String>, u64)>,
}

pub fn normalize_origin(origin: &str) -> Result<String, ConnectionError> {
    let parsed = Url::parse(origin.trim()).map_err(|_| ConnectionError::InvalidOrigin)?;
    let loopback = parsed
        .host_str()
        .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "[::1]");
    if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(ConnectionError::InvalidOrigin);
    }
    Ok(parsed.origin().ascii_serialization())
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

impl ConnectionAuthFlow {
    /// `pkce_verified` must only be true after this environment's PKCE support is verified.
    pub fn begin(origin: &str, profile: Profile) -> Result<Self, ConnectionError> {
        let origin = normalize_origin(origin)?;
        profile.validate()?;
        let auth = profile
            .authorization
            .as_ref()
            .ok_or(ConnectionError::InvalidResponse)?;
        if auth.kind == "device" {
            return Self::begin_device(&origin, profile);
        }
        let listener = TcpListener::bind(("127.0.0.1", auth.callback_port))
            .map_err(|_| ConnectionError::Network)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ConnectionError::Network)?;
        let redirect_uri = format!(
            "http://{}/callback",
            listener
                .local_addr()
                .map_err(|_| ConnectionError::Network)?
        );
        let state = Zeroizing::new(random_token());
        let verifier = auth.pkce.then(|| Zeroizing::new(random_token()));
        let mut url = endpoint(auth.origin.as_deref().unwrap_or(&origin), &auth.path)?;
        {
            let mut params = url.query_pairs_mut();
            params
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("state", &state);
            for (key, value) in &auth.params {
                params.append_pair(key, value);
            }
            if let Some(verifier) = &verifier {
                params
                    .append_pair("code_challenge_method", "S256")
                    .append_pair(
                        "code_challenge",
                        &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                    );
            }
        }
        Ok(Self {
            info: ConnectionAuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                authorize_url: url.to_string(),
                expires_at: (chrono::Utc::now() + chrono::Duration::seconds(AUTH_LIFETIME_SECONDS))
                    .to_rfc3339(),
                origin,
                user_code: None,
            },
            listener: Some(listener),
            state,
            verifier,
            redirect_uri,
            profile,
            started: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
            device: None,
        })
    }

    pub fn info(&self) -> ConnectionAuthStart {
        self.info.clone()
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Consumes the flow, so a callback cannot be exchanged twice. Run off the UI thread.
    pub fn complete(self, timeout: Duration) -> Result<ConnectionLoginResult, ConnectionError> {
        if self.device.is_some() {
            return self.complete_device(timeout);
        }
        let deadline =
            Instant::now() + timeout.min(Duration::from_secs(AUTH_LIFETIME_SECONDS as u64));
        loop {
            self.check_cancelled()?;
            if Instant::now() >= deadline
                || self.started.elapsed().as_secs() >= AUTH_LIFETIME_SECONDS as u64
            {
                return Err(ConnectionError::Timeout);
            }
            let (mut stream, address) = match self
                .listener
                .as_ref()
                .ok_or(ConnectionError::InvalidConfiguration)?
                .accept()
            {
                Ok(socket) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40));
                    continue;
                }
                Err(_) => return Err(ConnectionError::Network),
            };
            if !address.ip().is_loopback() {
                continue;
            }
            let target = match read_callback(&mut stream, &self.redirect_uri) {
                Ok(Some(target)) => target,
                Ok(None) => {
                    reply(&mut stream, false);
                    continue;
                }
                Err(error) => {
                    reply(&mut stream, false);
                    return Err(error);
                }
            };
            let parsed = Url::parse(&format!(
                "{}{}",
                self.redirect_uri.trim_end_matches("/callback"),
                target
            ))
            .map_err(|_| ConnectionError::InvalidResponse)?;
            let pairs: Vec<_> = parsed.query_pairs().collect();
            let state: Vec<_> = pairs.iter().filter(|(key, _)| key == "state").collect();
            if state.len() != 1 || state[0].1.as_ref() != self.state.as_str() {
                reply(&mut stream, false);
                return Err(ConnectionError::InvalidState);
            }
            if pairs.iter().any(|(key, _)| key == "error") {
                reply(&mut stream, false);
                return Err(ConnectionError::Cancelled);
            }
            let codes: Vec<_> = pairs.iter().filter(|(key, _)| key == "code").collect();
            if codes.len() != 1 || codes[0].1.is_empty() || codes[0].1.len() > 8192 {
                reply(&mut stream, false);
                return Err(ConnectionError::InvalidResponse);
            }
            let code = Zeroizing::new(codes[0].1.to_string());
            self.check_cancelled()?;
            let result = exchange_code(
                &self.info.origin,
                &self.profile,
                &self.redirect_uri,
                &code,
                self.verifier.as_ref().map(|value| value.as_str()),
            );
            self.check_cancelled()?;
            reply(&mut stream, result.is_ok());
            return result;
        }
    }

    fn check_cancelled(&self) -> Result<(), ConnectionError> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(ConnectionError::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn read_callback(
    stream: &mut TcpStream,
    redirect_uri: &str,
) -> Result<Option<String>, ConnectionError> {
    stream
        .set_nonblocking(false)
        .map_err(|_| ConnectionError::Network)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ConnectionError::Network)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ConnectionError::Network)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = [0u8; 1024];
    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| ConnectionError::InvalidResponse)?;
        if count == 0 || bytes.len() + count > 16384 {
            return Err(ConnectionError::InvalidResponse);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ConnectionError::InvalidResponse)?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    if first.next() != Some("GET") {
        return Ok(None);
    }
    let target = first.next().ok_or(ConnectionError::InvalidResponse)?;
    if target.split('?').next() != Some("/callback") {
        return Ok(None);
    }
    let expected_host = redirect_uri
        .trim_start_matches("http://")
        .trim_end_matches("/callback");
    let hosts: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case("host"))
        .collect();
    if hosts.len() != 1 || hosts[0].1.trim() != expected_host {
        return Err(ConnectionError::InvalidState);
    }
    Ok(Some(target.to_owned()))
}

fn reply(stream: &mut TcpStream, success: bool) {
    let body = if success {
        "Sign-in verified. Return to pman."
    } else {
        "Sign-in was not completed. Return to pman."
    };
    let status = if success { "200 OK" } else { "400 Bad Request" };
    let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len());
}

fn client() -> Result<Client, ConnectionError> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ConnectionError::Network)
}
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(v) if !v.is_empty() => Some(v.clone()),
        Value::Number(v) => Some(v.to_string()),
        _ => None,
    }
}
fn expand(template: &str, secret: &Value, target: &Url) -> Result<String, ConnectionError> {
    let mut output = String::new();
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("${") {
        output.push_str(before);
        let (key, tail) = after
            .split_once('}')
            .ok_or(ConnectionError::InvalidConfiguration)?;
        let value = if key == "origin" {
            Some(target.origin().ascii_serialization())
        } else if let Some(name) = key.strip_prefix("cookie:") {
            crate::http_proxy::cookie_pairs(secret, target)
                .map_err(|_| ConnectionError::InvalidResponse)?
                .into_iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v)
        } else if let Some(name) = key.strip_prefix("var:") {
            secret
                .get("variables")
                .and_then(|v| v.get(name))
                .and_then(text)
        } else if let Some(name) = key.strip_prefix("secret:") {
            secret.get(name).and_then(text)
        } else {
            secret
                .get("transient")
                .and_then(|v| v.get(key))
                .and_then(text)
        };
        output.push_str(&value.ok_or(ConnectionError::Expired)?);
        rest = tail;
    }
    output.push_str(rest);
    if output.len() > 65536 {
        return Err(ConnectionError::InvalidConfiguration);
    }
    Ok(output)
}
fn fields(
    values: &BTreeMap<String, String>,
    secret: &Value,
    target: &Url,
) -> Result<BTreeMap<String, String>, ConnectionError> {
    values
        .iter()
        .map(|(k, v)| Ok((k.clone(), expand(v, secret, target)?)))
        .collect()
}
fn render_json(value: &Value, secret: &Value, target: &Url) -> Result<Value, ConnectionError> {
    Ok(match value {
        Value::String(v) => Value::String(expand(v, secret, target)?),
        Value::Array(v) => Value::Array(
            v.iter()
                .map(|v| render_json(v, secret, target))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(v) => Value::Object(
            v.iter()
                .map(|(k, v)| Ok((k.clone(), render_json(v, secret, target)?)))
                .collect::<Result<_, ConnectionError>>()?,
        ),
        v => v.clone(),
    })
}
/// Cookie-derived values are resolved against the exact request URL each time.
/// Consequently a narrow or expired cookie cannot become a broad request header.
pub(crate) fn apply_auth(
    mut request: reqwest::blocking::RequestBuilder,
    secret: &Value,
    target: &Url,
) -> Result<reqwest::blocking::RequestBuilder, ConnectionError> {
    if secret
        .get("origin")
        .and_then(Value::as_str)
        .is_some_and(|v| v != target.origin().ascii_serialization())
    {
        return Err(ConnectionError::InvalidOrigin);
    }
    let config = profile(secret)?;
    let mut pairs = if secret.get("cookies").is_some() {
        crate::http_proxy::cookie_pairs(secret, target)
            .map_err(|_| ConnectionError::InvalidResponse)?
    } else {
        Vec::new()
    };
    for (name, template) in &config.cookies {
        let value = expand(template, secret, target)?;
        if !safe_cookie(name, &value) {
            return Err(ConnectionError::InvalidConfiguration);
        }
        pairs.retain(|(key, _)| key != name);
        pairs.push((name.clone(), value));
    }
    let mut headers = reqwest::header::HeaderMap::new();
    if !pairs.is_empty() {
        headers.insert(
            "Cookie",
            reqwest::header::HeaderValue::from_str(
                &pairs
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
            .map_err(|_| ConnectionError::InvalidResponse)?,
        );
    }
    for (key, value) in fields(&config.headers, secret, target)? {
        validate_header(&key)?;
        let value = reqwest::header::HeaderValue::from_str(&value)
            .map_err(|_| ConnectionError::InvalidConfiguration)?;
        headers.insert(
            reqwest::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|_| ConnectionError::InvalidConfiguration)?,
            value,
        );
    }
    request = request.headers(headers);
    Ok(request)
}
fn safe_cookie(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
        && value
            .bytes()
            .all(|c| (0x21..=0x7e).contains(&c) && !b"\";,\\".contains(&c))
}
fn add_cookie(
    secret: &mut Value,
    target: &Url,
    name: &str,
    value: &str,
) -> Result<(), ConnectionError> {
    if !safe_cookie(name, value) {
        return Err(ConnectionError::InvalidResponse);
    }
    if !secret["cookies"].is_array() {
        secret["cookies"] = json!([]);
    }
    let list = secret["cookies"]
        .as_array_mut()
        .ok_or(ConnectionError::InvalidResponse)?;
    list.retain(|v| v["name"] != name);
    list.push(json!({"name":name,"value":value,"domain":target.host_str(),"path":"/","secure":target.scheme()=="https","host_only":true,"http_only":true}));
    Ok(())
}
fn select(
    paths: &[String],
    body: &Value,
    headers: &reqwest::header::HeaderMap,
    secret: &Value,
    target: &Url,
) -> Option<String> {
    paths.iter().find_map(|path| {
        if let Some(name) = path.strip_prefix("header:") {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        } else if let Some(name) = path.strip_prefix("cookie:") {
            crate::http_proxy::cookie_pairs(secret, target)
                .ok()?
                .into_iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v)
        } else {
            body.pointer(path).and_then(text)
        }
    })
}
fn run_step(
    origin: &str,
    step: &Step,
    secret: &mut Value,
    authenticate: bool,
) -> Result<(Value, reqwest::header::HeaderMap), ConnectionError> {
    let target = endpoint(origin, &step.path)?;
    let method = if step.method.is_empty() {
        "GET"
    } else {
        &step.method
    };
    let mut request = client()?.request(
        reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| ConnectionError::InvalidConfiguration)?,
        target.clone(),
    );
    if authenticate {
        request = apply_auth(request, secret, &target)?;
    }
    request =
        request
            .header("Accept", "application/json")
            .query(&fields(&step.query, secret, &target)?);
    for (k, v) in fields(&step.headers, secret, &target)? {
        validate_header(&k)?;
        request = request.header(k, v);
    }
    if !step.form.is_empty() {
        request = request.form(&fields(&step.form, secret, &target)?);
    }
    if let Some(body) = &step.json {
        request = request.json(&render_json(body, secret, &target)?);
    }
    let mut response = request.send().map_err(|_| ConnectionError::Network)?;
    match response.status().as_u16() {
        400 => {}
        401 | 300..=399 => return Err(ConnectionError::Expired),
        403 => return Err(ConnectionError::Forbidden),
        200..=299 => {}
        _ => return Err(ConnectionError::Network),
    }
    let success = response.status().is_success();
    let headers = response.headers().clone();
    // reqwest's parser retains cookie scope. Do not broaden a Set-Cookie path/domain.
    let received = response.cookies().map(|c| json!({"name":c.name(),"value":c.value(),"domain":c.domain().unwrap_or(target.host_str().unwrap_or_default()),"path":c.path().unwrap_or_else(|| target.path().rsplit_once('/').map(|(p,_)|if p.is_empty(){"/"}else{p}).unwrap_or("/")),"host_only":c.domain().is_none(),"secure":c.secure(),"http_only":c.http_only(),"expires":c.expires().and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_secs())})).collect::<Vec<_>>();
    if !secret["cookies"].is_array() {
        secret["cookies"] = json!([]);
    }
    for cookie in received {
        let domain = cookie["domain"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches('.');
        if Some(domain) != target.host_str() {
            continue;
        }
        let list = secret["cookies"].as_array_mut().unwrap();
        list.retain(|c| {
            !(c["name"] == cookie["name"]
                && c["domain"] == cookie["domain"]
                && c["path"] == cookie["path"])
        });
        list.push(cookie);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .by_ref()
        .take(JSON_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConnectionError::Network)?;
    if bytes.len() as u64 > JSON_LIMIT {
        return Err(ConnectionError::InvalidResponse);
    }
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|_| ConnectionError::InvalidResponse)?;
    match body.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => return Err(ConnectionError::Pending),
        Some("slow_down") => return Err(ConnectionError::SlowDown),
        Some("access_denied") => return Err(ConnectionError::Cancelled),
        Some("expired_token") => return Err(ConnectionError::Expired),
        Some(_) => return Err(ConnectionError::InvalidResponse),
        None => {}
    }
    if !success {
        return Err(ConnectionError::InvalidResponse);
    }
    for (path, expected) in &step.expect {
        if body.pointer(path) != Some(expected) {
            return Err(ConnectionError::InvalidResponse);
        }
    }
    if let Some(path) = &step.cookie_header {
        if let Some(raw) = body.pointer(path).and_then(Value::as_str) {
            for pair in raw.split(';') {
                if let Some((name, value)) = pair.trim().split_once('=') {
                    add_cookie(secret, &target, name, value)?;
                }
            }
        }
    }
    if !secret["variables"].is_object() {
        secret["variables"] = json!({});
    }
    for (name, paths) in &step.extract {
        secret["variables"][name] = json!(select(paths, &body, &headers, secret, &target)
            .ok_or(ConnectionError::InvalidResponse)?);
    }
    for (name, paths) in &step.optional_extract {
        if let Some(value) = select(paths, &body, &headers, secret, &target) {
            secret["variables"][name] = json!(value);
        }
    }
    Ok((body, headers))
}
fn run_steps(origin: &str, steps: &[Step], secret: &mut Value) -> Result<(), ConnectionError> {
    for step in steps {
        if !step.skip_if_present.is_empty()
            && step
                .skip_if_present
                .iter()
                .all(|k| secret["variables"].get(k).and_then(text).is_some())
        {
            continue;
        }
        run_step(origin, step, secret, false)?;
    }
    Ok(())
}
fn exchange_code(
    origin: &str,
    config: &Profile,
    redirect_uri: &str,
    code: &str,
    verifier: Option<&str>,
) -> Result<ConnectionLoginResult, ConnectionError> {
    let mut secret = json!({"origin":origin,"auth_profile":config,"cookies":[],"variables":{},"transient":{"code":code,"redirect_uri":redirect_uri,"verifier":verifier.unwrap_or_default()}});
    let issuer = config
        .authorization
        .as_ref()
        .and_then(|a| a.origin.as_deref())
        .unwrap_or(origin);
    run_steps(issuer, &config.exchange, &mut secret)?;
    secret.as_object_mut().unwrap().remove("transient");
    let metadata = check_session(origin, &secret)?;
    Ok(ConnectionLoginResult { metadata, secret })
}
pub fn refresh_session(origin: &str, secret: &Value) -> Result<Value, ConnectionError> {
    let config = profile(secret)?;
    if config.refresh.is_empty() {
        return Err(ConnectionError::InvalidConfiguration);
    }
    let mut next = secret.clone();
    let issuer = config
        .authorization
        .as_ref()
        .and_then(|a| a.origin.as_deref())
        .unwrap_or(origin);
    run_steps(issuer, &config.refresh, &mut next)?;
    check_session(origin, &next)?;
    Ok(next)
}
pub fn check_session(
    origin: &str,
    secret: &Value,
) -> Result<ConnectionAccountMetadata, ConnectionError> {
    let origin = normalize_origin(origin)?;
    let config = profile(secret)?;
    let check = config
        .check
        .as_ref()
        .ok_or(ConnectionError::InvalidConfiguration)?;
    let mut material = secret.clone();
    let (body, headers) = run_step(&origin, &check.request, &mut material, true)?;
    let target = endpoint(&origin, &check.request.path)?;
    let user_id = select(&check.user_id, &body, &headers, &material, &target)
        .ok_or(ConnectionError::InvalidResponse)?;
    let tenant_key =
        select(&check.tenant_id, &body, &headers, &material, &target).unwrap_or_default();
    let account_id = format!(
        "account-{}",
        &hex::encode(Sha256::digest(
            format!("{origin}\0{tenant_key}\0{user_id}").as_bytes()
        ))[..24]
    );
    if secret
        .get("account_id")
        .and_then(Value::as_str)
        .is_some_and(|v| v != account_id)
    {
        return Err(ConnectionError::AccountMismatch);
    }
    let user_name = select(&check.user_name, &body, &headers, &material, &target)
        .unwrap_or_else(|| user_id.clone());
    let tenant_name =
        select(&check.tenant_name, &body, &headers, &material, &target).unwrap_or_default();
    // Only explicitly mapped display fields leave this module; never export credential values.
    for value in [&user_id, &tenant_key, &user_name, &tenant_name] {
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(ConnectionError::InvalidResponse);
        }
        if secret["variables"].as_object().is_some_and(|vars| {
            vars.values().any(|v| {
                v.as_str()
                    .is_some_and(|s| !s.is_empty() && value.contains(s))
            })
        }) || crate::http_proxy::cookie_pairs(secret, &target)
            .unwrap_or_default()
            .iter()
            .any(|(_, v)| !v.is_empty() && value.contains(v))
        {
            return Err(ConnectionError::InvalidResponse);
        }
    }
    Ok(ConnectionAccountMetadata {
        environment_id: format!(
            "service-{}",
            &hex::encode(Sha256::digest(origin.as_bytes()))[..24]
        ),
        account_id,
        origin,
        user_id,
        tenant_key,
        user_name,
        tenant_name,
        version: String::new(),
        status: "connected".into(),
        checked_at: chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    pub(super) fn server(
        responses: Vec<(u16, Value, Vec<(&'static str, &'static str)>)>,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            for (status, body, headers) in responses {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() > deadline {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0; 2048];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..end]);
                        let len = head
                            .lines()
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = tx.send(String::from_utf8(bytes).unwrap());
                let body = body.to_string();
                let extra = headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}\r\n"))
                    .collect::<String>();
                write!(stream,"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        (origin, rx, handle)
    }
    fn config() -> Profile {
        serde_json::from_value(json!({
        "authorization":{"path":"/authorize","params":{"client_id":"desktop"},"pkce":true},
        "exchange":[
            {"path":"/token","method":"POST","form":{"code":"${code}","redirect_uri":"${redirect_uri}","code_verifier":"${verifier}"},"extract":{"access":["/data/access"]}},
            {"path":"/session","method":"POST","query":{"access":"${var:access}"},"cookie_header":"/data/cookies","extract":{"session":["/data/session"]}}
        ],
        "headers":{"X-Session":"${cookie:SESSION}","X-Client":"desktop","Origin":"${origin}"},
        "cookies":{"mode":"agent"},
        "check":{"request":{"path":"/identity","method":"POST","json":{},"expect":{"/ok":true}},"user_id":["/data/id"],"tenant_id":["/data/tenant"],"user_name":["/data/name"]},
        "refresh":[{"path":"/renew","method":"POST","form":{"session":"${var:session}"},"cookie_header":"/cookies","extract":{"session":["/session"]}}]
    })).unwrap()
    }
    fn identity(id: &str) -> Value {
        json!({"ok":true,"data":{"id":id,"tenant":"org-a","name":"Demo User"}})
    }
    #[test]
    fn code_to_session_to_identity_and_request_injection() {
        // Finish the expensive KDF before the bounded HTTP fixture starts
        // waiting; parallel vault tests can otherwise exhaust its deadline.
        let dir = tempfile::tempdir().unwrap();
        let mut vault = crate::Vault::open(dir.path()).unwrap();
        vault.create("synthetic-master").unwrap();
        let (origin, requests, handle) = server(vec![
            (
                200,
                json!({"data":{"access":"synthetic-access-123"}}),
                vec![],
            ),
            (
                200,
                json!({"data":{"session":"synthetic-session-123","cookies":"SESSION=synthetic-session-123; language=en"}}),
                vec![],
            ),
            (200, identity("user-a"), vec![]),
            (200, json!({"ok":true}), vec![]),
        ]);
        let result = exchange_code(
            &origin,
            &config(),
            "http://127.0.0.1/callback",
            "synthetic-code",
            Some("synthetic-verifier"),
        )
        .unwrap();
        assert_eq!(result.metadata.user_id, "user-a");
        assert!(result.secret.get("transient").is_none());
        vault
            .add_site(crate::SiteInput::new(
                "demo",
                &origin,
                "authflow",
                result.secret.clone(),
            ))
            .unwrap();
        let site = vault.list_sites().unwrap().remove(0);
        let response = crate::http_proxy::execute(
            &site,
            &result.secret,
            "GET",
            "/resource",
            None,
            None,
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(response.status_code, 200);
        handle.join().unwrap();
        let requests = requests.try_iter().collect::<Vec<_>>();
        assert!(requests[0].contains("code=synthetic-code"));
        assert!(requests[1].contains("/session?access=synthetic-access-123"));
        assert!(requests[2].contains("x-session: synthetic-session-123"));
        assert!(requests[3].contains("mode=agent"));
        assert!(!serde_json::to_string(&result.metadata)
            .unwrap()
            .contains("synthetic-"));
    }
    #[test]
    fn browser_cookie_scope_is_preserved_when_mapped_to_headers() {
        let secret = json!({"origin":"https://service.test","auth_profile":{"headers":{"X-Session":"${cookie:SESSION}"}},"cookies":[{"name":"SESSION","value":"synthetic-session","domain":"service.test","path":"/api","secure":true,"host_only":true}]});
        let valid = Url::parse("https://service.test/api/user").unwrap();
        assert!(apply_auth(client().unwrap().get(valid.clone()), &secret, &valid).is_ok());
        for url in [
            "https://service.test/other",
            "https://other.test/api",
            "http://service.test/api",
        ] {
            let target = Url::parse(url).unwrap();
            assert!(apply_auth(client().unwrap().get(target.clone()), &secret, &target).is_err());
        }
    }
    #[test]
    fn refresh_is_atomic_and_account_changes_are_rejected() {
        let (origin, _, handle) = server(vec![
            (
                200,
                json!({"session":"synthetic-new","cookies":"SESSION=synthetic-new"}),
                vec![],
            ),
            (200, identity("user-b"), vec![]),
        ]);
        let old_id = format!(
            "account-{}",
            &hex::encode(Sha256::digest(
                format!("{origin}\0org-a\0user-a").as_bytes()
            ))[..24]
        );
        let secret = json!({"origin":origin,"auth_profile":config(),"variables":{"session":"synthetic-old"},"cookies":[],"account_id":old_id});
        assert!(matches!(
            refresh_session(&origin, &secret),
            Err(ConnectionError::AccountMismatch)
        ));
        assert_eq!(secret["variables"]["session"], "synthetic-old");
        handle.join().unwrap();
    }
    #[test]
    fn auth_state_pkce_cancel_and_cross_origin_configuration() {
        let flow = ConnectionAuthFlow::begin("https://service.test", config()).unwrap();
        let url = Url::parse(&flow.info().authorize_url).unwrap();
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "code_challenge_method" && v == "S256"));
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "state" && !v.is_empty()));
        flow.cancel();
        assert!(matches!(
            flow.complete(Duration::from_secs(1)),
            Err(ConnectionError::Cancelled)
        ));
        for path in ["//evil.test/token", "https://evil.test/token", "/../token"] {
            let mut profile = config();
            profile.exchange[0].path = path.into();
            assert!(profile.validate().is_err(), "accepted path: {path}");
        }
        let mut profile = config();
        profile
            .authorization
            .as_mut()
            .unwrap()
            .params
            .insert("state".into(), "attacker".into());
        assert!(profile.validate().is_err());
    }
    #[test]
    fn failure_status_and_invalid_identity_never_become_connected() {
        for (status, body, expected) in [
            (401, json!({}), "expired"),
            (403, json!({}), "forbidden"),
            (200, json!({"ok":false}), "invalid_response"),
        ] {
            let (origin, _, handle) = server(vec![(status, body, vec![])]);
            let secret = json!({"origin":origin,"auth_profile":config(),"cookies":{"SESSION":"synthetic-session"}});
            assert_eq!(
                check_session(&origin, &secret).unwrap_err().code(),
                expected
            );
            handle.join().unwrap();
        }
    }
    #[test]
    fn set_cookie_extraction_retains_scope_and_profile_unknown_keys_fail_closed() {
        let (origin, _, handle) = server(vec![(
            200,
            json!({}),
            vec![(
                "Set-Cookie",
                "SESSION=synthetic-cookie; Path=/api; HttpOnly",
            )],
        )]);
        let mut secret = json!({"origin":origin,"cookies":[],"variables":{}});
        let step: Step = serde_json::from_value(
            json!({"path":"/api/login","extract":{"session":["cookie:SESSION"]}}),
        )
        .unwrap();
        run_step(&origin, &step, &mut secret, false).unwrap();
        assert_eq!(secret["variables"]["session"], "synthetic-cookie");
        assert!(crate::http_proxy::cookie_pairs(
            &secret,
            &endpoint(&origin, "/elsewhere").unwrap()
        )
        .unwrap()
        .is_empty());
        handle.join().unwrap();
        assert!(profile(&json!({"auth_profile":{"script":"arbitrary code"}})).is_err());
    }
}

impl ConnectionAuthFlow {
    fn begin_device(origin: &str, profile: Profile) -> Result<Self, ConnectionError> {
        let auth = profile
            .authorization
            .as_ref()
            .ok_or(ConnectionError::InvalidConfiguration)?;
        let issuer = auth.origin.as_deref().unwrap_or(origin);
        let mut material = json!({"cookies":[],"variables":{}});
        let step = Step {
            path: auth.path.clone(),
            method: "POST".into(),
            form: auth.params.clone(),
            ..Step::default()
        };
        let (body, _) = run_step(issuer, &step, &mut material, false)?;
        let code = body["device_code"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(ConnectionError::InvalidResponse)?;
        let user_code = body["user_code"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            .ok_or(ConnectionError::InvalidResponse)?;
        let url = body["verification_uri_complete"]
            .as_str()
            .or_else(|| body["verification_uri"].as_str())
            .ok_or(ConnectionError::InvalidResponse)?;
        let parsed = Url::parse(url).map_err(|_| ConnectionError::InvalidResponse)?;
        normalize_origin(&parsed.origin().ascii_serialization())?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ConnectionError::InvalidResponse);
        }
        let interval = body["interval"].as_u64().unwrap_or(5).clamp(1, 60);
        let lifetime = body["expires_in"].as_i64().unwrap_or(600).clamp(1, 600);
        Ok(Self {
            info: ConnectionAuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                authorize_url: url.into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::seconds(lifetime)).to_rfc3339(),
                origin: origin.into(),
                user_code: Some(user_code.into()),
            },
            listener: None,
            state: Zeroizing::new(String::new()),
            verifier: None,
            redirect_uri: String::new(),
            profile,
            started: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
            device: Some((Zeroizing::new(code.into()), interval)),
        })
    }
    fn complete_device(self, timeout: Duration) -> Result<ConnectionLoginResult, ConnectionError> {
        let (code, mut interval) = self
            .device
            .as_ref()
            .ok_or(ConnectionError::InvalidConfiguration)?
            .clone();
        let expires = chrono::DateTime::parse_from_rfc3339(&self.info.expires_at)
            .map_err(|_| ConnectionError::InvalidResponse)?;
        let deadline = Instant::now() + timeout.min(Duration::from_secs(600));
        loop {
            let next = Instant::now() + Duration::from_secs(interval);
            while Instant::now() < next {
                self.check_cancelled()?;
                if Instant::now() >= deadline || chrono::Utc::now() >= expires {
                    return Err(ConnectionError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            match exchange_code(&self.info.origin, &self.profile, "", code.as_str(), None) {
                Ok(result) => {
                    self.check_cancelled()?;
                    return Ok(result);
                }
                Err(ConnectionError::Pending) => {}
                Err(ConnectionError::SlowDown) => interval = (interval + 5).min(60),
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod device_tests {
    use super::*;
    #[test]
    fn device_flow_polls_pending_and_finishes_with_scoped_identity() {
        let (origin, requests, handle) = super::tests::server(vec![
            (
                200,
                json!({"device_code":"synthetic-device","user_code":"ABCD-EFGH","verification_uri":"https://service.test/device","interval":1,"expires_in":30}),
                vec![],
            ),
            (400, json!({"error":"authorization_pending"}), vec![]),
            (
                200,
                json!({"access_token":"synthetic-device-token"}),
                vec![],
            ),
            (200, json!({"id":"user-device"}), vec![]),
        ]);
        let profile:Profile=serde_json::from_value(json!({"authorization":{"path":"/device","kind":"device","params":{"client_id":"desktop"}},"exchange":[{"path":"/token","method":"POST","form":{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"${code}"},"extract":{"access_token":["/access_token"]}}],"headers":{"Authorization":"Bearer ${var:access_token}"},"check":{"request":{"path":"/me"},"user_id":["/id"]}})).unwrap();
        let flow = ConnectionAuthFlow::begin(&origin, profile).unwrap();
        assert_eq!(flow.info().user_code.as_deref(), Some("ABCD-EFGH"));
        let result = flow.complete(Duration::from_secs(20)).unwrap();
        assert_eq!(result.metadata.user_id, "user-device");
        handle.join().unwrap();
        let requests = requests.try_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), 4);
        assert!(requests[3].contains("authorization: Bearer synthetic-device-token"));
    }
    #[test]
    fn forged_callback_state_does_not_exchange_a_code() {
        let profile:Profile=serde_json::from_value(json!({"authorization":{"path":"/authorize"},"exchange":[{"path":"/token"}],"check":{"request":{"path":"/me"},"user_id":["/id"]}})).unwrap();
        let flow = ConnectionAuthFlow::begin("https://service.test", profile).unwrap();
        let target = flow.listener.as_ref().unwrap().local_addr().unwrap();
        let thread = std::thread::spawn(move || flow.complete(Duration::from_secs(5)));
        let mut stream = TcpStream::connect(target).unwrap();
        write!(
            stream,
            "GET /callback?state=forged&code=synthetic-code HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .unwrap();
        assert!(matches!(
            thread.join().unwrap(),
            Err(ConnectionError::InvalidState)
        ));
    }
}
