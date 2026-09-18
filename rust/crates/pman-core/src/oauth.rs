//! OAuth provider flows with the same isolation guarantees as E10 login.
//!
//! Only officially supported secretless flows are implemented: GitLab
//! authorization-code + PKCE (loopback callback) and GitHub device flow.
//! Neither bundles a client secret; the user registers their own OAuth
//! application and configures the `client_id`. Tokens never leave the native
//! side: the frontend only sees `session_id`, `expires_at`, a status and a
//! redacted identity summary. Official references (checked 2026-09-19):
//! - GitLab OAuth2: https://docs.gitlab.com/ee/api/oauth2.html
//!   (authorization code with PKCE, token refresh, endpoints `/oauth/authorize`,
//!   `/oauth/token`; access tokens expire, refresh rotates both tokens)
//! - GitHub device flow: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
//!   (`POST /login/device/code`, poll `POST /login/oauth/access_token` with
//!   `grant_type=urn:ietf:params:oauth:grant-type:device_code`; no
//!   client_secret in the device flow; S256 PKCE exists only for the web flow)

use base64::Engine;
use crate::status::CheckEvidence;
use crate::{Vault, VaultError};
use rand::{rngs::OsRng, RngCore};
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

pub const PROVIDER_GITHUB: &str = "github";
pub const PROVIDER_GITLAB: &str = "gitlab";

/// Fixed loopback port so the user can register an exact redirect URI.
pub const GITLAB_LOOPBACK_PORT: u16 = 9867;
pub const GITLAB_REDIRECT_PATH: &str = "/callback";
const AUTH_LIFETIME_SECONDS: i64 = 600;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("OAuth origin must be an HTTPS origin (HTTP is allowed only on loopback)")]
    InvalidOrigin,
    #[error("client_id is required; register an OAuth application with the provider first")]
    MissingClient,
    #[error("OAuth state is missing or does not match; the callback was rejected")]
    InvalidState,
    #[error("OAuth login was denied by the provider or cancelled")]
    Cancelled,
    #[error("OAuth login timed out")]
    Timeout,
    #[error("OAuth network request failed")]
    Network,
    #[error("OAuth provider returned an invalid response")]
    InvalidResponse,
    #[error("the remote account does not match the account bound to this connection")]
    AccountMismatch,
    #[error("the loopback port needed for the OAuth callback is unavailable")]
    PortUnavailable,
}

impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidOrigin => "invalid_origin",
            Self::MissingClient => "oauth_unconfigured",
            Self::InvalidState => "invalid_state",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Network => "network_error",
            Self::InvalidResponse => "invalid_response",
            Self::AccountMismatch => "account_mismatch",
            Self::PortUnavailable => "port_unavailable",
        }
    }
}

/// Everything the management UI may see. No token material.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OAuthStart {
    pub session_id: String,
    pub provider: String,
    /// `browser` (GitLab: open the authorize URL) or `device` (GitHub: show
    /// the user code and open the verification URL).
    pub kind: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    pub expires_at: String,
    pub origin: String,
}

/// Secret-bearing result. Intentionally neither Debug nor Serialize.
pub struct OAuthResult {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Option<Zeroizing<String>>,
    pub expires_at: Option<String>,
    pub scope: String,
    /// Redacted display identity from the provider (login / username).
    pub account: String,
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

/// HTTPS origin or loopback HTTP, mirroring E10 login rules.
pub fn normalize_origin(origin: &str) -> Result<String, OAuthError> {
    let parsed = Url::parse(origin.trim()).map_err(|_| OAuthError::InvalidOrigin)?;
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
        return Err(OAuthError::InvalidOrigin);
    }
    Ok(parsed.origin().ascii_serialization())
}

// ---------------------------------------------------------------------------
// GitLab: authorization code + PKCE with a loopback callback listener.
// ---------------------------------------------------------------------------

pub struct GitLabOAuthFlow {
    info: OAuthStart,
    listener: TcpListener,
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    redirect_uri: String,
    origin: String,
    client_id: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}

impl GitLabOAuthFlow {
    pub fn begin(origin: &str, client_id: &str, scope: &str) -> Result<Self, OAuthError> {
        let origin = normalize_origin(origin)?;
        if !valid_client_id(client_id) {
            return Err(OAuthError::MissingClient);
        }
        let listener = TcpListener::bind(("127.0.0.1", GITLAB_LOOPBACK_PORT))
            .map_err(|_| OAuthError::PortUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| OAuthError::Network)?;
        let redirect_uri =
            format!("http://127.0.0.1:{GITLAB_LOOPBACK_PORT}{GITLAB_REDIRECT_PATH}");
        let state = Zeroizing::new(random_token());
        let verifier = Zeroizing::new(random_token());
        let mut url = Url::parse(&format!("{origin}/oauth/authorize"))
            .map_err(|_| OAuthError::InvalidOrigin)?;
        {
            let mut params = url.query_pairs_mut();
            params
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", scope)
                .append_pair("state", state.as_str())
                .append_pair("code_challenge_method", "S256")
                .append_pair(
                    "code_challenge",
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(Sha256::digest(verifier.as_bytes())),
                );
        }
        Ok(Self {
            info: OAuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                provider: PROVIDER_GITLAB.into(),
                kind: "browser".into(),
                url: url.to_string(),
                user_code: None,
                expires_at: (chrono::Utc::now()
                    + chrono::Duration::seconds(AUTH_LIFETIME_SECONDS))
                .to_rfc3339(),
                origin: origin.clone(),
            },
            listener,
            state,
            verifier,
            redirect_uri,
            origin,
            client_id: client_id.to_owned(),
            started: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn info(&self) -> OAuthStart {
        self.info.clone()
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Consumes the flow: a callback can never be exchanged twice.
    pub fn complete(self, timeout: Duration) -> Result<OAuthResult, OAuthError> {
        let deadline =
            Instant::now() + timeout.min(Duration::from_secs(AUTH_LIFETIME_SECONDS as u64));
        loop {
            self.check_cancelled()?;
            if Instant::now() >= deadline
                || self.started.elapsed().as_secs() >= AUTH_LIFETIME_SECONDS as u64
            {
                return Err(OAuthError::Timeout);
            }
            let (mut stream, address) = match self.listener.accept() {
                Ok(socket) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40));
                    continue;
                }
                Err(_) => return Err(OAuthError::Network),
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
            let parsed = Url::parse(&format!("http://127.0.0.1{target}"))
                .map_err(|_| OAuthError::InvalidResponse)?;
            let pairs: Vec<_> = parsed.query_pairs().collect();
            let state: Vec<_> = pairs.iter().filter(|(key, _)| key == "state").collect();
            if state.len() != 1 || state[0].1.as_ref() != self.state.as_str() {
                reply(&mut stream, false);
                return Err(OAuthError::InvalidState);
            }
            if pairs.iter().any(|(key, _)| key == "error") {
                reply(&mut stream, false);
                return Err(OAuthError::Cancelled);
            }
            let codes: Vec<_> = pairs.iter().filter(|(key, _)| key == "code").collect();
            if codes.len() != 1 || codes[0].1.is_empty() || codes[0].1.len() > 8192 {
                reply(&mut stream, false);
                return Err(OAuthError::InvalidResponse);
            }
            let code = Zeroizing::new(codes[0].1.to_string());
            self.check_cancelled()?;
            let exchange = exchange_gitlab_code(
                &self.origin,
                &self.client_id,
                &self.redirect_uri,
                &code,
                &self.verifier,
            );
            self.check_cancelled()?;
            let result = match exchange {
                Ok(result) => result,
                Err(error) => {
                    reply(&mut stream, false);
                    return Err(error);
                }
            };
            reply(&mut stream, true);
            return Ok(result);
        }
    }

    fn check_cancelled(&self) -> Result<(), OAuthError> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(OAuthError::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn exchange_gitlab_code(
    origin: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<OAuthResult, OAuthError> {
    let body = serde_json::to_string(&json!({
        "client_id": client_id,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }))
    .map_err(|_| OAuthError::InvalidResponse)?;
    let tokens = token_request(&format!("{origin}/oauth/token"), &body)?;
    let identity = fetch_json(&format!("{origin}/api/v4/user"), tokens.access_token.as_str())?;
    let account = identity
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if account.is_empty() || account.len() > 128 {
        return Err(OAuthError::InvalidResponse);
    }
    Ok(OAuthResult {
        account,
        ..result_from_tokens(tokens)
    })
}

fn result_from_tokens(tokens: OAuthTokens) -> OAuthResult {
    OAuthResult {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_at,
        scope: tokens.scope,
        account: String::new(),
    }
}

// ---------------------------------------------------------------------------
// GitHub: device flow (no client secret, no PKCE by design).
// ---------------------------------------------------------------------------

pub struct GitHubDeviceFlow {
    info: OAuthStart,
    device_code: Zeroizing<String>,
    client_id: String,
    token_endpoint: String,
    identity_endpoint: String,
    interval: Duration,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}

impl GitHubDeviceFlow {
    /// Official endpoint entry point. Tests inject a local fake provider via
    /// `begin_at`; production always uses the real endpoints.
    pub fn begin(client_id: &str, scope: &str) -> Result<Self, OAuthError> {
        Self::begin_at("https://api.github.com", "https://github.com", client_id, scope)
    }

    pub fn begin_at(
        api_base: &str,
        device_base: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<Self, OAuthError> {
        if !valid_client_id(client_id) {
            return Err(OAuthError::MissingClient);
        }
        let body = format!(
            "client_id={}&scope={}",
            urlencode(client_id),
            urlencode(scope)
        );
        let response = post_form(&format!("{device_base}/login/device/code"), &body)?;
        let device_code = response
            .get("device_code")
            .and_then(Value::as_str)
            .ok_or(OAuthError::InvalidResponse)?;
        let user_code = response
            .get("user_code")
            .and_then(Value::as_str)
            .ok_or(OAuthError::InvalidResponse)?
            .to_owned();
        let interval = response
            .get("interval")
            .and_then(Value::as_u64)
            .unwrap_or(5)
            .clamp(1, 60);
        let expires_in = response.get("expires_in").and_then(Value::as_u64).unwrap_or(900);
        Ok(Self {
            info: OAuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                provider: PROVIDER_GITHUB.into(),
                kind: "device".into(),
                url: response
                    .get("verification_uri")
                    .and_then(Value::as_str)
                    .unwrap_or("https://github.com/login/device")
                    .to_owned(),
                user_code: Some(user_code),
                expires_at: (chrono::Utc::now()
                    + chrono::Duration::seconds(expires_in.min(3600) as i64))
                .to_rfc3339(),
                origin: device_base.to_owned(),
            },
            device_code: Zeroizing::new(device_code.to_owned()),
            client_id: client_id.to_owned(),
            token_endpoint: format!("{device_base}/login/oauth/access_token"),
            identity_endpoint: format!("{api_base}/user"),
            interval: Duration::from_secs(interval),
            started: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn info(&self) -> OAuthStart {
        self.info.clone()
    }
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Polls the token endpoint. `slow_down` extends the interval; the device
    /// code expiry is honoured; cancellation stops between polls.
    pub fn complete(self, timeout: Duration) -> Result<OAuthResult, OAuthError> {
        let deadline =
            Instant::now() + timeout.min(Duration::from_secs(AUTH_LIFETIME_SECONDS as u64));
        let mut interval = self.interval;
        loop {
            self.check_cancelled()?;
            if Instant::now() >= deadline || self.started.elapsed() > Duration::from_secs(3600) {
                return Err(OAuthError::Timeout);
            }
            std::thread::sleep(interval);
            self.check_cancelled()?;
            let body = format!(
                "client_id={}&device_code={}&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
                urlencode(&self.client_id),
                urlencode(self.device_code.as_str())
            );
            let response = match post_form(&self.token_endpoint, &body) {
                Ok(response) => response,
                Err(_) => return Err(OAuthError::Network),
            };
            if let Some(access) = response.get("access_token").and_then(Value::as_str) {
                if access.is_empty() || access.len() > 4096 {
                    return Err(OAuthError::InvalidResponse);
                }
                let access_token = Zeroizing::new(access.to_owned());
                let refresh_token = response
                    .get("refresh_token")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(|value| Zeroizing::new(value.to_owned()));
                let expires_in = response.get("expires_in").and_then(Value::as_i64);
                let expires_at = expires_in.map(|seconds| {
                    (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339()
                });
                let scope = response
                    .get("scope")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let identity =
                    fetch_json(&self.identity_endpoint, access_token.as_str())?;
                let account = identity
                    .get("login")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if account.is_empty() || account.len() > 128 {
                    return Err(OAuthError::InvalidResponse);
                }
                return Ok(OAuthResult {
                    access_token,
                    refresh_token,
                    expires_at,
                    scope,
                    account,
                });
            }
            match response.get("error").and_then(Value::as_str) {
                Some("authorization_pending") => continue,
                Some("slow_down") => {
                    interval += Duration::from_secs(5);
                    continue;
                }
                Some("expired_token") => return Err(OAuthError::Timeout),
                Some("access_denied") => return Err(OAuthError::Cancelled),
                Some(_) => return Err(OAuthError::InvalidResponse),
                None => return Err(OAuthError::InvalidResponse),
            }
        }
    }

    fn check_cancelled(&self) -> Result<(), OAuthError> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(OAuthError::Cancelled)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Token refresh. Rotation is persisted atomically by the caller.
// ---------------------------------------------------------------------------

pub fn refresh_gitlab_tokens(
    origin: &str,
    client_id: &str,
    refresh_token: &str,
    redirect_uri: &str,
) -> Result<OAuthTokens, OAuthError> {
    let origin = normalize_origin(origin)?;
    if !valid_client_id(client_id) {
        return Err(OAuthError::MissingClient);
    }
    let body = serde_json::to_string(&json!({
        "client_id": client_id,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "redirect_uri": redirect_uri,
    }))
    .map_err(|_| OAuthError::InvalidResponse)?;
    token_request(&format!("{origin}/oauth/token"), &body)
}

pub fn refresh_github_tokens(
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, OAuthError> {
    refresh_github_tokens_at("https://github.com", client_id, refresh_token)
}

pub fn refresh_github_tokens_at(
    device_base: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, OAuthError> {
    if !valid_client_id(client_id) {
        return Err(OAuthError::MissingClient);
    }
    // The GitHub refresh grant needs client_id + refresh_token; the optional
    // client_secret is deliberately omitted (public client).
    let body = serde_json::to_string(&json!({
        "client_id": client_id,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }))
    .map_err(|_| OAuthError::InvalidResponse)?;
    token_request(&format!("{device_base}/login/oauth/access_token"), &body)
}

/// Secret-bearing token fields. Never serialized or logged.
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Option<Zeroizing<String>>,
    pub expires_at: Option<String>,
    pub scope: String,
}


// ---------------------------------------------------------------------------
// Vault persistence. Tokens live only inside the encrypted secret.
// ---------------------------------------------------------------------------

/// Provider tokens decoded from a stored secret. Used by refresh.
pub fn stored_refresh_token(secret: &Value) -> Option<String> {
    secret
        .get("oauth_refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub fn stored_client_id(details: &crate::ConnectionDetails) -> Option<String> {
    details
        .oauth_client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

impl Vault {
    /// Persist OAuth login: bind the account, store tokens in the secret and
    /// record sanitized evidence. The previous context's grants were already
    /// revoked if the account changed (update_details rules); a mismatch with
    /// an existing bound account is rejected instead of overwritten.
    pub fn finish_oauth_login(
        &mut self,
        alias: &str,
        provider: &str,
        result: &OAuthResult,
    ) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        let details = self.details(alias)?;
        let bound = details.extra.get("account_id").and_then(Value::as_str);
        if let Some(bound) = bound.filter(|value| !value.is_empty()) {
            if bound != result.account {
                return Err(VaultError::InvalidSchema(
                    "account_mismatch: 远端账号与连接绑定账号不一致；请为其他账号新建连接".into(),
                ));
            }
        }
        if !details.account.is_empty() && details.account != result.account {
            return Err(VaultError::InvalidSchema(
                "account_mismatch: 远端账号与连接绑定账号不一致；请为其他账号新建连接".into(),
            ));
        }
        let mut secret = serde_json::Map::new();
        secret.insert("token".into(), json!(result.access_token.as_str()));
        if let Some(refresh) = &result.refresh_token {
            secret.insert("oauth_refresh_token".into(), json!(refresh.as_str()));
        }
        if let Some(expires_at) = &result.expires_at {
            secret.insert("oauth_token_expires_at".into(), json!(expires_at));
        }
        secret.insert("oauth_scope".into(), json!(result.scope));
        secret.insert("provider".into(), json!(provider));
        self.update_secret(alias, Value::Object(secret))?;
        let mut extra = details.extra.clone();
        if !extra.is_object() {
            extra = json!({});
        }
        extra["account_id"] = json!(result.account);
        let patch = if details.account.is_empty() {
            json!({"account": result.account, "extra": extra})
        } else {
            json!({"extra": extra})
        };
        self.update_details(alias, patch)?;
        self.record_check_evidence(
            alias,
            crate::status::DIMENSION_IDENTITY,
            CheckEvidence {
                state: "verified".into(),
                checked_at: crate::vault::now(),
                message: format!("{provider} OAuth 登录成功，远端确认账号身份"),
                provider: Some(provider.to_owned()),
                account: Some(result.account.clone()),
                scope: Some("OAuth 登录（浏览器/设备授权）".into()),
                ..CheckEvidence::default()
            },
        )?;
        Ok(())
    }

    /// Refresh stored tokens for one connection (single-flight is enforced by
    /// the caller). Atomic: the secret is written once with both new tokens.
    pub fn refresh_connection_tokens(
        &mut self,
        alias: &str,
        expected_origin: Option<&str>,
    ) -> Result<String, VaultError> {
        self.ensure_unlocked()?;
        let site = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        let details = self.details(alias)?;
        let provider = details
            .provider
            .clone()
            .unwrap_or_else(|| {
                let host = url::Url::parse(&site.site_url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                    .unwrap_or_default();
                if host == "api.github.com" {
                    PROVIDER_GITHUB.into()
                } else {
                    PROVIDER_GITLAB.into()
                }
            });
        let client_id = stored_client_id(&details).ok_or_else(|| {
            VaultError::InvalidSchema("oauth_unconfigured: 未配置 OAuth 应用 client_id".into())
        })?;
        let secret = self.get_site_secret(alias)?;
        let refresh_token = stored_refresh_token(&secret).ok_or_else(|| {
            VaultError::InvalidSchema("此连接没有可刷新的 OAuth 令牌，请重新登录".into())
        })?;
        let tokens = match provider.as_str() {
            PROVIDER_GITHUB => refresh_github_tokens(&client_id, &refresh_token)
                .map_err(|error| VaultError::InvalidSchema(error.to_string()))?,
            _ => refresh_gitlab_tokens(
                expected_origin.unwrap_or(&site.site_url),
                &client_id,
                &refresh_token,
                &format!("http://127.0.0.1:{GITLAB_LOOPBACK_PORT}{GITLAB_REDIRECT_PATH}"),
            )
            .map_err(|error| VaultError::InvalidSchema(error.to_string()))?,
        };
        // Atomic persist: merge into the current secret and write once.
        let mut updated = secret.clone();
        updated["token"] = json!(tokens.access_token.as_str());
        if let Some(refresh) = &tokens.refresh_token {
            updated["oauth_refresh_token"] = json!(refresh.as_str());
        }
        if let Some(expires_at) = &tokens.expires_at {
            updated["oauth_token_expires_at"] = json!(expires_at);
        }
        self.update_secret(alias, updated)?;
        Ok(format!("{provider} 令牌已刷新"))
    }
}

// ---------------------------------------------------------------------------
// Transport helpers. Responses are size-capped; secrets stay local.
// ---------------------------------------------------------------------------

fn token_request(endpoint: &str, json_body: &str) -> Result<OAuthTokens, OAuthError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| OAuthError::Network)?;
    let response = client
        .post(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .body(json_body.to_owned())
        .send()
        .map_err(|_| OAuthError::Network)?;
    let status = response.status();
    let bytes: Vec<u8> = response
        .bytes()
        .map_err(|_| OAuthError::Network)?
        .to_vec();
    if bytes.len() > 512 * 1024 {
        return Err(OAuthError::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)?;
    if !status.is_success() {
        let error = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("invalid_response");
        if error == "invalid_grant" || error == "expired_token" {
            return Err(OAuthError::Timeout);
        }
        return Err(OAuthError::InvalidResponse);
    }
    let access_token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4096)
        .ok_or(OAuthError::InvalidResponse)?;
    Ok(OAuthTokens {
        access_token: Zeroizing::new(access_token.to_owned()),
        refresh_token: value
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|value| Zeroizing::new(value.to_owned())),
        expires_at: value.get("expires_in").and_then(Value::as_i64).map(|seconds| {
            (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339()
        }),
        scope: value
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

fn fetch_json(endpoint: &str, access_token: &str) -> Result<Value, OAuthError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| OAuthError::Network)?;
    let response = client
        .get(endpoint)
        .header("Accept", "application/json")
        .header("User-Agent", crate::http_proxy::USER_AGENT)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .map_err(|_| OAuthError::Network)?;
    if !response.status().is_success() {
        return Err(OAuthError::InvalidResponse);
    }
    let bytes: Vec<u8> = response
        .bytes()
        .map_err(|_| OAuthError::Network)?
        .to_vec();
    if bytes.len() > 512 * 1024 {
        return Err(OAuthError::InvalidResponse);
    }
    serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)
}

fn post_form(endpoint: &str, form: &str) -> Result<Value, OAuthError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| OAuthError::Network)?;
    let response = client
        .post(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form.to_owned())
        .send()
        .map_err(|_| OAuthError::Network)?;
    let bytes: Vec<u8> = response
        .bytes()
        .map_err(|_| OAuthError::Network)?
        .to_vec();
    if bytes.len() > 512 * 1024 {
        return Err(OAuthError::InvalidResponse);
    }
    serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn read_callback(
    stream: &mut TcpStream,
    redirect_uri: &str,
) -> Result<Option<String>, OAuthError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| OAuthError::Network)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| OAuthError::Network)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = [0u8; 1024];
    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| OAuthError::InvalidResponse)?;
        if count == 0 || bytes.len() + count > 16384 {
            return Err(OAuthError::InvalidResponse);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let text = std::str::from_utf8(bytes.as_slice()).map_err(|_| OAuthError::InvalidResponse)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("GET") {
        return Err(OAuthError::InvalidResponse);
    }
    let prefix = redirect_uri
        .trim_end_matches(GITLAB_REDIRECT_PATH)
        .trim_end_matches('/');
    if !target.starts_with(GITLAB_REDIRECT_PATH)
        && !target.starts_with(&format!("{prefix}{GITLAB_REDIRECT_PATH}"))
    {
        return Ok(None);
    }
    Ok(Some(target.to_owned()))
}

fn reply(stream: &mut TcpStream, ok: bool) {
    let body = if ok {
        "<!doctype html><title>pman</title><p>登录已完成，请返回 pman。此窗口可以关闭。</p>"
    } else {
        "<!doctype html><title>pman</title><p>登录未完成，请返回 pman 重试。</p>"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Mutex;

    const SECRET_TOKEN: &str = "SYNTHETIC_OAT_NEVER_OUTPUT_10928";
    const SECRET_REFRESH: &str = "SYNTHETIC_REFRESH_NEVER_OUTPUT_77341";
    const SECRET_DEVICE_CODE: &str = "SYNTHETIC_DEVICE_CODE_NEVER_OUTPUT_55812";

    /// The GitLab flow always binds the same fixed loopback port; tests that
    /// use it must not run concurrently with each other.
    static PORT_LOCK: Mutex<()> = Mutex::new(());

    type Request = (String, String);

    /// Minimal stateful fake provider: every accepted request is passed to the
    /// handler with (path, body) and the handler returns the raw response.
    struct FakeProvider {
        address: String,
        requests: std::sync::Arc<Mutex<Vec<Request>>>,
        shutdown: std::sync::mpsc::Sender<()>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeProvider {
        fn start(handler: impl Fn(&Request) -> String + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let (shutdown, receiver) = std::sync::mpsc::channel();
            let requests: std::sync::Arc<Mutex<Vec<Request>>> = Default::default();
            let log = requests.clone();
            let thread = std::thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                loop {
                    if receiver.try_recv().is_ok() {
                        break;
                    }
                    let mut stream = match listener.accept() {
                        Ok((stream, _)) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                            continue;
                        }
                        Err(_) => break,
                    };
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 8192];
                    loop {
                        let size = match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(size) => size,
                        };
                        bytes.extend_from_slice(&buffer[..size]);
                        if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    let path = text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    let body = text
                        .split("\r\n\r\n")
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    log.lock().unwrap().push((path.clone(), body.clone()));
                    let response = handler(&(path, body));
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self {
                address,
                requests,
                shutdown,
                thread: Some(thread),
            }
        }

        fn base(&self) -> String {
            format!("http://{}", self.address)
        }

        fn paths(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|(path, _)| path.clone())
                .collect()
        }

        fn json_response(body: Value) -> String {
            let body = serde_json::to_vec(&body).unwrap();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(&body)
            )
        }
    }

    impl Drop for FakeProvider {
        fn drop(&mut self) {
            let _ = self.shutdown.send(());
            // Wake the accept loop so the provider thread can observe shutdown.
            let _ = TcpStream::connect(&self.address);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn query_param(url: &str, name: &str) -> String {
        Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .unwrap_or_default()
    }

    fn send_callback(target: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", GITLAB_LOOPBACK_PORT))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        Ok(response)
    }

    #[test]
    fn gitlab_flow_success_binds_pkce_state_and_identity() {
        let _port = PORT_LOCK.lock().unwrap();
        let challenge: std::sync::Arc<Mutex<String>> = Default::default();
        let server_challenge = challenge.clone();
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/oauth/token" {
                let payload: Value = serde_json::from_str(body).unwrap();
                assert_eq!(payload["grant_type"], "authorization_code");
                assert_eq!(payload["code"], "test-code");
                // PKCE S256: the verifier sent to the token endpoint must hash
                // to the challenge embedded in the authorize URL.
                let verifier = payload["code_verifier"].as_str().unwrap();
                let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(verifier.as_bytes()));
                assert_eq!(
                    digest,
                    server_challenge.lock().unwrap().as_str(),
                    "code_verifier does not match the authorize challenge"
                );
                assert!(
                    payload.get("client_secret").is_none(),
                    "PKCE flow must not send a secret"
                );
                FakeProvider::json_response(json!({
                    "access_token": SECRET_TOKEN,
                    "refresh_token": SECRET_REFRESH,
                    "expires_in": 7200,
                    "scope": "read_user"
                }))
            } else if path == "/api/v4/user" {
                FakeProvider::json_response(json!({"username": "gitlab-user", "id": 7}))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let flow =
            GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let info = flow.info();
        assert_eq!(info.kind, "browser");
        assert_eq!(info.provider, "gitlab");
        *challenge.lock().unwrap() = query_param(&info.url, "code_challenge");
        assert!(!query_param(&info.url, "state").is_empty());

        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        let state = query_param(&info.url, "state");
        let response =
            send_callback(&format!("/callback?code=test-code&state={state}")).unwrap();
        handle.join().unwrap();
        assert!(response.contains("200 OK"), "{response}");
        let result = done.lock().unwrap().take().expect("flow finished");
        let result = result.expect("flow should succeed");
        assert_eq!(result.account, "gitlab-user");
        assert_eq!(result.access_token.as_str(), SECRET_TOKEN);
        assert_eq!(
            result.refresh_token.as_ref().unwrap().as_str(),
            SECRET_REFRESH
        );
        assert!(result.expires_at.is_some());
    }

    #[test]
    fn wrong_state_is_rejected_before_any_token_exchange() {
        let _port = PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, _)| {
            if path.starts_with("/oauth/token") {
                panic!("token endpoint must not be reached with a bad state");
            }
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let flow =
            GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        send_callback("/callback?code=test-code&state=forged-state").unwrap();
        handle.join().unwrap();
        let outcome = done.lock().unwrap().take().expect("flow finished");
        assert!(matches!(outcome, Err(OAuthError::InvalidState)));
        assert!(
            !provider
                .paths()
                .iter()
                .any(|path| path.starts_with("/oauth/token")),
            "被拒绝的回调不得触发令牌交换"
        );
    }

    #[test]
    fn provider_denied_callback_is_reported_as_cancelled() {
        let _port = PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, _)| {
            if path.starts_with("/oauth/token") {
                panic!("denied callback must not exchange anything");
            }
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let flow =
            GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let state = query_param(&flow.info().url, "state");
        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        // A spec-compliant error redirect still carries the state parameter.
        send_callback(&format!("/callback?error=access_denied&error_description=no&state={state}"))
            .unwrap();
        handle.join().unwrap();
        let outcome = done.lock().unwrap().take().expect("flow finished");
        assert!(matches!(outcome, Err(OAuthError::Cancelled)));
    }

    #[test]
    fn cancelling_the_flow_stops_completion() {
        let _port = PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |_request| {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let flow =
            GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let cancellation = flow.cancellation();
        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        std::thread::sleep(Duration::from_millis(100));
        cancellation.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        let outcome = done.lock().unwrap().take().expect("flow finished");
        assert!(matches!(outcome, Err(OAuthError::Cancelled)));
    }

    #[test]
    fn missing_callback_times_out() {
        let _port = PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |_request| {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let flow =
            GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let outcome = flow.complete(Duration::from_millis(300));
        assert!(matches!(outcome, Err(OAuthError::Timeout)));
    }

    #[test]
    fn a_consumed_flow_rejects_duplicate_callbacks() {
        let _port = PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, _body)| {
            if path == "/oauth/token" {
                FakeProvider::json_response(json!({
                    "access_token": SECRET_TOKEN,
                    "refresh_token": SECRET_REFRESH,
                    "expires_in": 7200,
                    "scope": "read_user"
                }))
            } else if path == "/api/v4/user" {
                FakeProvider::json_response(json!({"username": "gitlab-user"}))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let flow =
            GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let info = flow.info();
        let state = query_param(&info.url, "state");
        let done: std::sync::Arc<Mutex<Option<bool>>> = Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome.is_ok());
        });
        let first = send_callback(&format!("/callback?code=one&state={state}")).unwrap();
        handle.join().unwrap();
        assert!(done.lock().unwrap().take().unwrap(), "first callback completes");
        assert!(first.contains("200 OK"));
        // The flow has been consumed: the listener is gone, so a replayed
        // callback cannot be exchanged a second time.
        assert!(send_callback(&format!("/callback?code=two&state={state}")).is_err());
        let exchanges = provider
            .paths()
            .iter()
            .filter(|path| path.starts_with("/oauth/token"))
            .count();
        assert_eq!(exchanges, 1, "令牌交换只能发生一次");
    }

    #[test]
    fn oauth_login_binds_account_and_a_second_account_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "gitlab",
                "https://gitlab.example.test",
                "api_token",
                json!({"token": "placeholder"}),
            ))
            .unwrap();
        let result = OAuthResult {
            access_token: Zeroizing::new(SECRET_TOKEN.to_owned()),
            refresh_token: Some(Zeroizing::new(SECRET_REFRESH.to_owned())),
            expires_at: Some("2026-09-19T12:00:00Z".into()),
            scope: "read_user".into(),
            account: "first-user".into(),
        };
        vault.finish_oauth_login("gitlab", "gitlab", &result).unwrap();
        let secret = vault.get_site_secret("gitlab").unwrap();
        assert_eq!(secret["token"], json!(SECRET_TOKEN));
        assert_eq!(secret["oauth_refresh_token"], json!(SECRET_REFRESH));
        let details = vault.details("gitlab").unwrap();
        assert_eq!(details.account, "first-user");
        assert_eq!(details.extra["account_id"], json!("first-user"));
        let status = vault.connection_status("gitlab").unwrap();
        assert_eq!(status.identity.state, crate::status::STATE_VERIFIED);

        // A different remote account must never overwrite the binding.
        let second = OAuthResult {
            account: "second-user".into(),
            ..result
        };
        let error = vault
            .finish_oauth_login("gitlab", "gitlab", &second)
            .unwrap_err();
        assert!(error.to_string().contains("account_mismatch"));
        assert_eq!(vault.details("gitlab").unwrap().account, "first-user");
        assert_eq!(
            vault.get_site_secret("gitlab").unwrap()["token"],
            json!(SECRET_TOKEN),
            "被拒绝的登录不得写入任何令牌"
        );
    }

    #[test]
    fn refresh_rotates_tokens_atomically_and_requires_configuration() {
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/oauth/token" {
                let payload: Value = serde_json::from_str(body).unwrap();
                assert_eq!(payload["grant_type"], "refresh_token");
                assert_eq!(payload["refresh_token"], SECRET_REFRESH);
                assert!(payload.get("client_secret").is_none());
                FakeProvider::json_response(json!({
                    "access_token": "ROTATED_TOKEN_VALUE_000001",
                    "refresh_token": "ROTATED_REFRESH_VALUE_000001",
                    "expires_in": 7200,
                    "scope": "read_user"
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(
                crate::SiteInput::new(
                    "gitlab",
                    &provider.base(),
                    "api_token",
                    json!({"token": SECRET_TOKEN, "oauth_refresh_token": SECRET_REFRESH}),
                ),
            )
            .unwrap();
        vault
            .update_details(
                "gitlab",
                json!({"oauth_client_id": "client-id-1", "provider": "gitlab"}),
            )
            .unwrap();
        // Unconfigured connections never reach the network.
        vault
            .update_details("gitlab", json!({"oauth_client_id": null}))
            .unwrap();
        assert!(vault.refresh_connection_tokens("gitlab", None).is_err());
        vault
            .update_details("gitlab", json!({"oauth_client_id": "client-id-1"}))
            .unwrap();
        let message = vault.refresh_connection_tokens("gitlab", None).unwrap();
        assert!(message.contains("已刷新"));
        let secret = vault.get_site_secret("gitlab").unwrap();
        assert_eq!(secret["token"], json!("ROTATED_TOKEN_VALUE_000001"));
        assert_eq!(
            secret["oauth_refresh_token"],
            json!("ROTATED_REFRESH_VALUE_000001")
        );
        assert_eq!(
            vault.details("gitlab").unwrap().extra["account_id"],
            serde_json::Value::Null,
            "刷新不改变账号绑定"
        );
    }

    #[test]
    fn github_device_flow_polls_until_success_and_fetches_identity() {
        let polls: std::sync::Arc<Mutex<usize>> = Default::default();
        let server_polls = polls.clone();
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/login/device/code" {
                assert!(body.contains("client_id=client-id-9"));
                FakeProvider::json_response(json!({
                    "device_code": SECRET_DEVICE_CODE,
                    "user_code": "ABCD-1234",
                    "verification_uri": "https://github.com/login/device",
                    "interval": 1,
                    "expires_in": 900
                }))
            } else if path == "/login/oauth/access_token" {
                let mut count = server_polls.lock().unwrap();
                *count += 1;
                if *count == 1 {
                    FakeProvider::json_response(json!({"error": "authorization_pending"}))
                } else if *count == 2 {
                    FakeProvider::json_response(json!({"error": "slow_down", "interval": 1}))
                } else {
                    // The device flow polls with form-encoded parameters.
                    assert!(
                        body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"),
                        "{body}"
                    );
                    assert!(body.contains("client_id=client-id-9"));
                    assert!(!body.contains("client_secret="));
                    FakeProvider::json_response(json!({
                        "access_token": SECRET_TOKEN,
                        "refresh_token": SECRET_REFRESH,
                        "expires_in": 28800,
                        "scope": "repo"
                    }))
                }
            } else if path == "/user" {
                FakeProvider::json_response(json!({"login": "octocat"}))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let flow =
            GitHubDeviceFlow::begin_at(&provider.base(), &provider.base(), "client-id-9", "repo")
                .unwrap();
        let info = flow.info();
        assert_eq!(info.kind, "device");
        assert_eq!(info.user_code.as_deref(), Some("ABCD-1234"));
        let result = flow.complete(Duration::from_secs(30)).unwrap();
        assert_eq!(result.account, "octocat");
        assert_eq!(result.access_token.as_str(), SECRET_TOKEN);
        assert!(*polls.lock().unwrap() >= 3, "should have polled pending+slow_down+success");
    }

    #[test]
    fn github_device_flow_maps_denied_and_expired_outcomes() {
        // Access denied stops with a cancelled error, not a retry loop.
        let provider = FakeProvider::start(move |(path, _body)| {
            if path == "/login/device/code" {
                FakeProvider::json_response(json!({
                    "device_code": SECRET_DEVICE_CODE,
                    "user_code": "ABCD-5678",
                    "verification_uri": "https://github.com/login/device",
                    "interval": 1,
                    "expires_in": 900
                }))
            } else if path == "/login/oauth/access_token" {
                FakeProvider::json_response(json!({"error": "access_denied"}))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let flow =
            GitHubDeviceFlow::begin_at(&provider.base(), &provider.base(), "client-id-9", "repo")
                .unwrap();
        assert!(matches!(
            flow.complete(Duration::from_secs(10)),
            Err(OAuthError::Cancelled)
        ));

        // Expired device codes stop immediately.
        let provider = FakeProvider::start(move |(path, _body)| {
            if path == "/login/device/code" {
                FakeProvider::json_response(json!({
                    "device_code": SECRET_DEVICE_CODE,
                    "user_code": "ABCD-9012",
                    "verification_uri": "https://github.com/login/device",
                    "interval": 1,
                    "expires_in": 900
                }))
            } else if path == "/login/oauth/access_token" {
                FakeProvider::json_response(json!({"error": "expired_token"}))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let flow =
            GitHubDeviceFlow::begin_at(&provider.base(), &provider.base(), "client-id-9", "repo")
                .unwrap();
        assert!(matches!(
            flow.complete(Duration::from_secs(10)),
            Err(OAuthError::Timeout)
        ));
    }

    #[test]
    fn oauth_start_information_never_contains_secret_material() {
        let provider = FakeProvider::start(move |(path, _body)| {
            if path == "/login/device/code" {
                FakeProvider::json_response(json!({
                    "device_code": SECRET_DEVICE_CODE,
                    "user_code": "ABCD-0000",
                    "verification_uri": "https://github.com/login/device",
                    "interval": 1,
                    "expires_in": 900
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            }
        });
        let flow =
            GitHubDeviceFlow::begin_at(&provider.base(), &provider.base(), "client-id-9", "repo")
                .unwrap();
        let info = flow.info();
        let serialized = serde_json::to_string(&info).unwrap();
        assert!(!serialized.contains(SECRET_DEVICE_CODE), "{serialized}");
        assert!(serialized.contains("ABCD-0000"));
    }
}
