//! E10 login provider. Only `E10AccountMetadata` may cross the management UI boundary.
//! Codes, cookies and access tokens stay inside the broker; errors never contain URLs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::{Client, Response};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

const AUTH_LIFETIME_SECONDS: i64 = 600;
const JSON_LIMIT: u64 = 512 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum E10Error {
    #[error("E10 origin must be an HTTPS origin (HTTP is allowed only on loopback)")]
    InvalidOrigin,
    #[error("invalid E10 agent type")]
    InvalidAgentType,
    #[error("E10 callback state is missing or does not match; use isolated website login if this environment does not return state")]
    InvalidState,
    #[error("E10 login was cancelled")]
    Cancelled,
    #[error("E10 login timed out")]
    Timeout,
    #[error("E10 authentication has expired; sign in again")]
    Expired,
    #[error("E10 permission was denied")]
    Forbidden,
    #[error("E10 network request failed")]
    Network,
    #[error("E10 returned an invalid authentication response")]
    InvalidResponse,
    #[error("E10 account does not match the account bound to this connection")]
    AccountMismatch,
}

impl E10Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidOrigin => "invalid_origin",
            Self::InvalidAgentType => "invalid_request",
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
pub struct E10AuthStart {
    pub session_id: String,
    pub authorize_url: String,
    pub expires_at: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct E10AccountMetadata {
    pub environment_id: String,
    pub account_id: String,
    pub origin: String,
    pub user_id: String,
    pub tenant_key: String,
    pub user_name: String,
    pub tenant_name: String,
    pub version: String,
    pub agent_type: String,
    pub status: String,
    pub checked_at: String,
}

// Intentionally neither Debug nor Serialize: callers must persist secret separately.
pub struct E10LoginResult {
    pub metadata: E10AccountMetadata,
    pub secret: Value,
}

pub struct E10AuthFlow {
    info: E10AuthStart,
    listener: TcpListener,
    state: Zeroizing<String>,
    verifier: Option<Zeroizing<String>>,
    redirect_uri: String,
    agent_type: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}

pub fn normalize_origin(origin: &str) -> Result<String, E10Error> {
    let parsed = Url::parse(origin.trim()).map_err(|_| E10Error::InvalidOrigin)?;
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
        return Err(E10Error::InvalidOrigin);
    }
    Ok(parsed.origin().ascii_serialization())
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn valid_agent(agent: &str) -> bool {
    !agent.is_empty()
        && agent.len() <= 64
        && agent
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

impl E10AuthFlow {
    /// `pkce_verified` must only be true after this environment's PKCE support is verified.
    pub fn begin(origin: &str, agent_type: &str, pkce_verified: bool) -> Result<Self, E10Error> {
        let origin = normalize_origin(origin)?;
        if !valid_agent(agent_type) {
            return Err(E10Error::InvalidAgentType);
        }
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| E10Error::Network)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| E10Error::Network)?;
        let redirect_uri = format!(
            "http://{}/callback",
            listener.local_addr().map_err(|_| E10Error::Network)?
        );
        let state = Zeroizing::new(random_token());
        let verifier = pkce_verified.then(|| Zeroizing::new(random_token()));
        let mut url = Url::parse(&format!("{origin}/papi/sso/oauth2.0/authorize"))
            .map_err(|_| E10Error::InvalidOrigin)?;
        {
            let mut params = url.query_pairs_mut();
            params
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("access_type", "agent")
                .append_pair("agent_type", agent_type)
                .append_pair("state", &state);
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
            info: E10AuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                authorize_url: url.to_string(),
                expires_at: (chrono::Utc::now() + chrono::Duration::seconds(AUTH_LIFETIME_SECONDS))
                    .to_rfc3339(),
                origin,
            },
            listener,
            state,
            verifier,
            redirect_uri,
            agent_type: agent_type.to_owned(),
            started: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn info(&self) -> E10AuthStart {
        self.info.clone()
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Consumes the flow, so a callback cannot be exchanged twice. Run off the UI thread.
    pub fn complete(self, timeout: Duration) -> Result<E10LoginResult, E10Error> {
        let deadline =
            Instant::now() + timeout.min(Duration::from_secs(AUTH_LIFETIME_SECONDS as u64));
        loop {
            self.check_cancelled()?;
            if Instant::now() >= deadline
                || self.started.elapsed().as_secs() >= AUTH_LIFETIME_SECONDS as u64
            {
                return Err(E10Error::Timeout);
            }
            let (mut stream, address) = match self.listener.accept() {
                Ok(socket) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40));
                    continue;
                }
                Err(_) => return Err(E10Error::Network),
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
            .map_err(|_| E10Error::InvalidResponse)?;
            let pairs: Vec<_> = parsed.query_pairs().collect();
            let state: Vec<_> = pairs.iter().filter(|(key, _)| key == "state").collect();
            if state.len() != 1 || state[0].1.as_ref() != self.state.as_str() {
                reply(&mut stream, false);
                return Err(E10Error::InvalidState);
            }
            if pairs.iter().any(|(key, _)| key == "error") {
                reply(&mut stream, false);
                return Err(E10Error::Cancelled);
            }
            let codes: Vec<_> = pairs.iter().filter(|(key, _)| key == "code").collect();
            if codes.len() != 1 || codes[0].1.is_empty() || codes[0].1.len() > 8192 {
                reply(&mut stream, false);
                return Err(E10Error::InvalidResponse);
            }
            let code = Zeroizing::new(codes[0].1.to_string());
            self.check_cancelled()?;
            let result = exchange_code(
                &self.info.origin,
                &self.agent_type,
                &self.redirect_uri,
                &code,
                self.verifier.as_ref().map(|value| value.as_str()),
            );
            self.check_cancelled()?;
            reply(&mut stream, result.is_ok());
            return result;
        }
    }

    fn check_cancelled(&self) -> Result<(), E10Error> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(E10Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn read_callback(stream: &mut TcpStream, redirect_uri: &str) -> Result<Option<String>, E10Error> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| E10Error::Network)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| E10Error::Network)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = [0u8; 1024];
    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| E10Error::InvalidResponse)?;
        if count == 0 || bytes.len() + count > 16384 {
            return Err(E10Error::InvalidResponse);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| E10Error::InvalidResponse)?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    if first.next() != Some("GET") {
        return Ok(None);
    }
    let target = first.next().ok_or(E10Error::InvalidResponse)?;
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
        return Err(E10Error::InvalidState);
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

fn client() -> Result<Client, E10Error> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| E10Error::Network)
}

fn response_json(mut response: Response) -> Result<Value, E10Error> {
    match response.status().as_u16() {
        401 => return Err(E10Error::Expired),
        403 => return Err(E10Error::Forbidden),
        300..=399 => return Err(E10Error::Expired),
        200..=299 => {}
        _ => return Err(E10Error::Network),
    }
    let mut body = Zeroizing::new(Vec::new());
    response
        .by_ref()
        .take(JSON_LIMIT + 1)
        .read_to_end(&mut body)
        .map_err(|_| E10Error::Network)?;
    if body.len() as u64 > JSON_LIMIT {
        return Err(E10Error::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(&body).map_err(|_| E10Error::InvalidResponse)?;
    if !value.is_object() {
        return Err(E10Error::InvalidResponse);
    }
    match value.get("code").and_then(Value::as_i64) {
        Some(401) => return Err(E10Error::Expired),
        Some(403) => return Err(E10Error::Forbidden),
        _ => {}
    }
    if value.get("loginStatus") == Some(&Value::Bool(false)) {
        return Err(E10Error::Expired);
    }
    Ok(value)
}

fn field(value: &Value, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| {
            value.get(name).and_then(|value| match value {
                Value::String(text) if !text.is_empty() => Some(text.clone()),
                Value::Number(number) => Some(number.to_string()),
                _ => None,
            })
        })
        .unwrap_or_default()
}

fn unwrap_data(value: &Value) -> &Value {
    value
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(value)
}

fn exchange_code(
    origin: &str,
    agent_type: &str,
    redirect_uri: &str,
    code: &str,
    verifier: Option<&str>,
) -> Result<E10LoginResult, E10Error> {
    let client = client()?;
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(verifier) = verifier {
        params.push(("code_verifier", verifier));
    }
    let response = client
        .post(format!("{origin}/papi/sso/oauth2.0/accessToken"))
        .form(&params)
        .send()
        .map_err(|_| E10Error::Network)?;
    let mut header_sid = String::new();
    for header in response.headers().get_all("set-cookie") {
        if let Ok(header) = header.to_str() {
            if let Some(value) = header
                .split(';')
                .next()
                .and_then(|part| part.strip_prefix("ETEAMSID="))
            {
                header_sid = value.to_owned();
            }
        }
    }
    let token_response = response_json(response)?;
    let token = unwrap_data(&token_response);
    let mut sid = field(token, &["eteamsId", "eteamsid", "ETEAMSID"]);
    if sid.is_empty() {
        sid = header_sid;
    }
    let mut raw = field(token, &["cookies", "cookie"]);
    let mut version = field(token, &["version", "baselineVersion"]);
    let access_token = Zeroizing::new(field(token, &["access_token", "accessToken"]));
    if !access_token.is_empty() && (sid.is_empty() || raw.is_empty()) {
        // This E10 API requires the access token as a query parameter. Neither this
        // URL nor reqwest error details are exposed outside the provider.
        let profile_response = client
            .post(format!("{origin}/papi/sso/oauth2.0/profile"))
            .query(&[("access_token", access_token.as_str())])
            .header("Accept", "application/json")
            .send()
            .map_err(|_| E10Error::Network)?;
        let profile_response = response_json(profile_response)?;
        let profile = unwrap_data(&profile_response);
        if sid.is_empty() {
            sid = field(profile, &["eteamsId", "eteamsid", "ETEAMSID"]);
        }
        if raw.is_empty() {
            raw = field(profile, &["cookies", "cookie"]);
        }
        if version.is_empty() {
            version = field(profile, &["version", "baselineVersion"]);
        }
    }
    let mut secret = secret_from_cookie_header(origin, agent_type, &raw, &sid)?;
    secret["version"] = Value::String(version);
    let metadata = check_session(origin, &secret)?;
    Ok(E10LoginResult { metadata, secret })
}

/// Converts the E10 profile's Cookie request header to host-bound records.
pub fn secret_from_cookie_header(
    origin: &str,
    agent_type: &str,
    raw: &str,
    eteamsid: &str,
) -> Result<Value, E10Error> {
    let origin = normalize_origin(origin)?;
    if !valid_agent(agent_type) {
        return Err(E10Error::InvalidAgentType);
    }
    let parsed = Url::parse(&origin).map_err(|_| E10Error::InvalidOrigin)?;
    let mut cookies = Vec::new();
    let mut sid = eteamsid.to_owned();
    for pair in raw.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name.eq_ignore_ascii_case("ETEAMSID") {
            if sid.is_empty() {
                sid = value.to_owned();
            }
            continue;
        }
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "agenttype" | "isagent" | "expires" | "max-age" | "domain" | "path" | "samesite"
        ) {
            continue;
        }
        if !safe_cookie(name, value) {
            return Err(E10Error::InvalidResponse);
        }
        cookies.push(json!({"name":name,"value":value,"domain":parsed.host_str(),"path":"/","host_only":true,"secure":parsed.scheme()=="https","http_only":true,"expires":null}));
    }
    if sid.is_empty() || !safe_cookie("ETEAMSID", &sid) {
        return Err(E10Error::InvalidResponse);
    }
    cookies.push(json!({"name":"ETEAMSID","value":sid,"domain":parsed.host_str(),"path":"/","host_only":true,"secure":parsed.scheme()=="https","http_only":true,"expires":null}));
    Ok(json!({"origin":origin,"agent_type":agent_type,"eteamsid":sid,"cookies":cookies}))
}

fn safe_cookie(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        && value
            .bytes()
            .all(|byte| byte >= 0x21 && byte <= 0x7e && !b"\";,\\".contains(&byte))
}

/// Checks the session without returning cookies or accepting an old cached identity.
pub fn check_session(origin: &str, secret: &Value) -> Result<E10AccountMetadata, E10Error> {
    let origin = normalize_origin(origin)?;
    if secret.get("origin").and_then(Value::as_str) != Some(origin.as_str()) {
        return Err(E10Error::InvalidOrigin);
    }
    let target = Url::parse(&format!("{origin}/api/baseserver/layout/teamsCheck"))
        .map_err(|_| E10Error::InvalidOrigin)?;
    let (sid, cookie, agent) = request_auth(secret, &target)?;
    let response = client()?
        .post(target)
        .query(&[
            ("clientType", "not_xinchuang"),
            ("client", "WEB"),
            ("domainName", origin.as_str()),
        ])
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("eteamsid", sid)
        .header("Cookie", cookie)
        .header("agentType", &agent)
        .header("isAgent", "true")
        .header("User-Agent", format!("AgentType={agent},IsAgent=true"))
        .header("Origin", &origin)
        .send()
        .map_err(|_| E10Error::Network)?;
    let header_employee = response
        .headers()
        .get("employeeId")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let value = response_json(response)?;
    let data = unwrap_data(&value);
    let current = data.get("currentUser").unwrap_or(&Value::Null);
    let tenant = data.get("currentTenant").unwrap_or(&Value::Null);
    let mut user_id = field(current, &["employeeId", "id", "userId"]);
    if user_id.is_empty() {
        user_id = field(data, &["employeeId", "userId"]);
    }
    if user_id.is_empty() {
        user_id = header_employee;
    }
    if user_id.is_empty() {
        return Err(E10Error::InvalidResponse);
    }
    let mut tenant_key = field(current, &["tenantKey"]);
    if tenant_key.is_empty() {
        tenant_key = field(tenant, &["tenantKey"]);
    }
    if tenant_key.is_empty() {
        tenant_key = field(data, &["tenantKey"]);
    }
    let environment_id = format!(
        "e10-{}",
        &hex::encode(Sha256::digest(origin.as_bytes()))[..24]
    );
    let account_id = format!(
        "account-{}",
        &hex::encode(Sha256::digest(
            format!("{origin}\0{tenant_key}\0{user_id}").as_bytes()
        ))[..24]
    );
    if secret
        .get("account_id")
        .and_then(Value::as_str)
        .is_some_and(|bound| bound != account_id)
    {
        return Err(E10Error::AccountMismatch);
    }
    Ok(E10AccountMetadata {
        environment_id,
        account_id,
        origin,
        user_id,
        tenant_key,
        user_name: field(current, &["userName", "username", "name", "employeeName"]),
        tenant_name: field(tenant, &["tenantName", "name"]),
        version: field(secret, &["version"]),
        agent_type: agent,
        status: "connected".to_owned(),
        checked_at: chrono::Utc::now().to_rfc3339(),
    })
}

pub(crate) fn request_auth(
    secret: &Value,
    target: &Url,
) -> Result<(String, String, String), E10Error> {
    let origin = secret
        .get("origin")
        .and_then(Value::as_str)
        .ok_or(E10Error::InvalidOrigin)?;
    if normalize_origin(origin)? != target.origin().ascii_serialization() {
        return Err(E10Error::InvalidOrigin);
    }
    let agent = secret
        .get("agent_type")
        .and_then(Value::as_str)
        .unwrap_or("Codex");
    if !valid_agent(agent) {
        return Err(E10Error::InvalidAgentType);
    }
    let mut pairs =
        crate::http_proxy::cookie_pairs(secret, target).map_err(|_| E10Error::InvalidResponse)?;
    let sid = pairs
        .iter()
        .find(|(name, _)| name == "ETEAMSID")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
        .ok_or(E10Error::Expired)?;
    pairs
        .retain(|(name, _)| !matches!(name.to_ascii_lowercase().as_str(), "agenttype" | "isagent"));
    pairs.push(("agentType".to_owned(), agent.to_owned()));
    pairs.push(("isAgent".to_owned(), "true".to_owned()));
    Ok((
        sid,
        pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
        agent.to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn server(
        responses: Vec<(u16, Value)>,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                loop {
                    let count = stream.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&request[..end]);
                        let length = header
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                sender
                    .send(String::from_utf8_lossy(&request).to_string())
                    .unwrap();
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (origin, receiver, handle)
    }

    fn identity() -> Value {
        json!({"data":{"currentUser":{"employeeId":"user-1","tenantKey":"tenant-1","name":"Test User"},"currentTenant":{"name":"Test Tenant"}}})
    }

    #[test]
    fn e10_origin_requires_exact_origin_and_stable_normalization() {
        assert_eq!(
            normalize_origin("https://E10.EXAMPLE:443/").unwrap(),
            "https://e10.example"
        );
        for invalid in [
            "http://e10.example",
            "https://e10.example/app",
            "https://user:pass@e10.example",
            "https://e10.example/?secret=x",
            "https://e10.example/#x",
        ] {
            assert_eq!(normalize_origin(invalid), Err(E10Error::InvalidOrigin));
        }
    }

    #[test]
    fn e10_pkce_is_explicit_and_state_is_unique() {
        let flow = E10AuthFlow::begin("https://e10.example", "Codex", false).unwrap();
        let pkce = E10AuthFlow::begin("https://e10.example", "Codex", true).unwrap();
        let url = Url::parse(&flow.info().authorize_url).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert!(query.get("state").is_some_and(|state| state.len() >= 43));
        assert!(!query.contains_key("code_challenge"));
        assert!(pkce
            .info()
            .authorize_url
            .contains("code_challenge_method=S256"));
        assert_ne!(flow.state.as_str(), pkce.state.as_str());
        assert_eq!(
            E10AuthFlow::begin("https://e10.example", "Codex;evil", false).err(),
            Some(E10Error::InvalidAgentType)
        );
    }

    #[test]
    fn e10_cancel_and_timeout_never_exchange_codes() {
        let flow = E10AuthFlow::begin("https://e10.example", "Codex", false).unwrap();
        flow.cancel();
        assert_eq!(
            flow.complete(Duration::from_secs(1)).err(),
            Some(E10Error::Cancelled)
        );
        let flow = E10AuthFlow::begin("https://e10.example", "Codex", false).unwrap();
        assert_eq!(flow.complete(Duration::ZERO).err(), Some(E10Error::Timeout));
    }

    #[test]
    fn e10_callback_rejects_missing_mismatched_and_duplicate_state() {
        for query in [
            "code=synthetic",
            "code=synthetic&state=wrong",
            "code=synthetic&state=wrong&state=other",
        ] {
            let flow = E10AuthFlow::begin("https://e10.example", "Codex", false).unwrap();
            let url = format!("{}?{query}", flow.redirect_uri);
            let callback = std::thread::spawn(move || {
                client().unwrap().get(url).send().unwrap().status().as_u16()
            });
            assert_eq!(
                flow.complete(Duration::from_secs(5)).err(),
                Some(E10Error::InvalidState)
            );
            assert_eq!(callback.join().unwrap(), 400);
        }
    }

    #[test]
    fn e10_login_exchanges_code_and_verifies_remote_identity_without_exporting_secret() {
        let (origin, requests, handle) = server(vec![
            (200, json!({"access_token":"synthetic-access-token"})),
            (
                200,
                json!({"eteamsId":"synthetic-session-cookie","cookies":"langType=7; ETEAMSID=synthetic-session-cookie","version":"2607"}),
            ),
            (200, identity()),
        ]);
        let flow = E10AuthFlow::begin(&origin, "Codex", true).unwrap();
        let url = format!(
            "{}?code=synthetic-code&state={}",
            flow.redirect_uri,
            flow.state.as_str()
        );
        let callback = std::thread::spawn(move || {
            client().unwrap().get(url).send().unwrap().status().as_u16()
        });
        let result = flow.complete(Duration::from_secs(5)).unwrap();
        assert_eq!(callback.join().unwrap(), 200);
        handle.join().unwrap();
        assert_eq!(result.metadata.user_id, "user-1");
        assert_eq!(result.metadata.tenant_key, "tenant-1");
        assert_eq!(result.metadata.version, "2607");
        assert!(!serde_json::to_string(&result.metadata)
            .unwrap()
            .contains("synthetic"));
        let token = requests.recv().unwrap();
        let profile = requests.recv().unwrap();
        let check = requests.recv().unwrap().to_ascii_lowercase();
        assert!(token.contains("code=synthetic-code") && token.contains("code_verifier="));
        assert!(profile.contains("access_token=synthetic-access-token"));
        assert!(check.contains("eteamsid: synthetic-session-cookie"));
        assert!(check.contains("agenttype=codex,isagent=true"));
        assert!(check.contains("agenttype=codex; isagent=true"));
        assert!(check.contains("langtype=7"));
        assert_eq!(result.secret["cookies"][0]["host_only"], true);
    }

    #[test]
    fn e10_health_distinguishes_expired_forbidden_and_schema_failure() {
        for (status, body, expected) in [
            (401, json!({}), E10Error::Expired),
            (403, json!({}), E10Error::Forbidden),
            (200, json!({}), E10Error::InvalidResponse),
            (200, json!({"code":401}), E10Error::Expired),
        ] {
            let (origin, _requests, handle) = server(vec![(status, body)]);
            let secret =
                secret_from_cookie_header(&origin, "Codex", "", "synthetic-session-cookie")
                    .unwrap();
            assert_eq!(check_session(&origin, &secret).err(), Some(expected));
            handle.join().unwrap();
        }
    }

    #[test]
    fn e10_health_checks_pin_account_and_session_scope() {
        let (origin, _requests, handle) = server(vec![(200, identity())]);
        let mut secret =
            secret_from_cookie_header(&origin, "Codex", "", "synthetic-session-cookie").unwrap();
        secret["account_id"] = json!("another-account");
        assert_eq!(
            check_session(&origin, &secret).err(),
            Some(E10Error::AccountMismatch)
        );
        handle.join().unwrap();
        let other = Url::parse("https://other.example/").unwrap();
        assert_eq!(
            request_auth(&secret, &other).err(),
            Some(E10Error::InvalidOrigin)
        );
        secret["cookies"][0]["expires"] = json!(0);
        assert_eq!(
            request_auth(&secret, &Url::parse(&origin).unwrap()).err(),
            Some(E10Error::Expired)
        );
    }

    #[test]
    fn e10_cookie_filter_preserves_domain_path_secure_and_expiry() {
        let secret = json!({"origin":"https://e10.example","agent_type":"Codex","cookies":[
            {"name":"ETEAMSID","value":"synthetic-session-cookie","domain":"e10.example","path":"/","secure":true},
            {"name":"cross","value":"blocked","domain":"other.example","path":"/"},
            {"name":"narrow","value":"blocked","domain":"e10.example","path":"/admin"},
            {"name":"old","value":"blocked","domain":"e10.example","path":"/","expires":0},
            {"name":"matching","value":"kept","domain":".e10.example","path":"/api"}
        ]});
        let (_, cookie, _) = request_auth(
            &secret,
            &Url::parse("https://e10.example/api/check").unwrap(),
        )
        .unwrap();
        assert!(cookie.contains("matching=kept"));
        assert!(!cookie.contains("blocked"));
        let insecure = crate::http_proxy::cookie_pairs(
            &secret,
            &Url::parse("http://e10.example/api/check").unwrap(),
        )
        .unwrap();
        assert!(!insecure.iter().any(|(name, _)| name == "ETEAMSID"));
        let sibling = crate::http_proxy::cookie_pairs(
            &secret,
            &Url::parse("https://e10.example/apix").unwrap(),
        )
        .unwrap();
        assert!(!sibling.iter().any(|(name, _)| name == "matching"));
    }
}
