//! OAuth provider flows with the same isolation guarantees as Connection login.
//!
//! Only officially supported secretless flows are implemented: authorization
//! code + PKCE (loopback callback) for GitLab, Microsoft and Google, the
//! GitHub device flow, and the E10 platform-private authorization-code
//! variant (no client id, no secret; see OAUTH-PROVIDERS.md §2.5). None of
//! them bundles a client secret; the user registers their own OAuth
//! application and configures the `client_id` (E10 needs neither). Tokens
//! never leave the native side: the frontend only sees `session_id`,
//! `expires_at`, a status and a redacted identity summary. Official
//! references (checked 2026-09-19, re-checked 2026-09-21):
//! - GitLab OAuth2: https://docs.gitlab.com/ee/api/oauth2.html
//!   (authorization code with PKCE, token refresh, endpoints `/oauth/authorize`,
//!   `/oauth/token`; access tokens expire, refresh rotates both tokens)
//! - GitHub device flow: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
//!   (`POST /login/device/code`, poll `POST /login/oauth/access_token` with
//!   `grant_type=urn:ietf:params:oauth:grant-type:device_code`; no
//!   client_secret in the device flow; the web flow now accepts PKCE
//!   parameters but its token exchange still requires client_secret)
//! - Microsoft auth code + PKCE (public client):
//!   https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
//!   ("Public clients ... must not use secrets or certificates when redeeming
//!   an authorization code"; loopback `http://localhost` redirect; refresh
//!   without secret; `offline_access` is required for a refresh token)
//! - Google installed-app flow:
//!   https://developers.google.com/identity/protocols/oauth2/native-app
//!   (PKCE supported; `client_secret` is optional at exchange and refresh
//!   because "installed apps can't keep secrets"); identity via
//!   https://developers.google.com/identity/openid-connect/openid-connect
//! - Gitee: https://gitee.com/api/v5/oauth_doc — the authorization-code
//!   exchange REQUIRES client_secret (no PKCE, no device flow) → no Gitee
//!   OAuth; the Token path stays (identity check in `check.rs`).
//! - E10 (private platform, no public docs): endpoints extracted from the
//!   e10-login@1.5.0 CLI source — authorize `{origin}/papi/sso/oauth2.0/authorize`
//!   (`access_type=agent`), token `POST {origin}/papi/sso/oauth2.0/accessToken`
//!   (form, no client id/secret), profile fallback
//!   `POST {origin}/papi/sso/oauth2.0/profile`; the reference CLI sends no
//!   state, so pman always sends one and reports `state_not_returned` when
//!   the platform omits it (the desktop falls back to the WebView2 login).

use crate::status::CheckEvidence;
use crate::{Vault, VaultError};
use base64::Engine;
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
pub const PROVIDER_MICROSOFT: &str = "microsoft";
pub const PROVIDER_GOOGLE: &str = "google";
pub const PROVIDER_E10: &str = "e10";
/// Token-only provider: no OAuth flow (the official exchange requires a
/// client secret), but `check.rs` still verifies PAT identity.
pub const PROVIDER_GITEE: &str = "gitee";

/// Fixed loopback ports so the user can register an exact redirect URI.
pub const GITLAB_LOOPBACK_PORT: u16 = 9867;
pub const MICROSOFT_LOOPBACK_PORT: u16 = 9868;
pub const GOOGLE_LOOPBACK_PORT: u16 = 9869;
/// e10-login's default callback port; keep the redirect registration stable.
pub const E10_LOOPBACK_PORT: u16 = 19800;
pub const OAUTH_REDIRECT_PATH: &str = "/callback";
const AUTH_LIFETIME_SECONDS: i64 = 600;

// E10 platform-private endpoints (e10-login@1.5.0 contract).
const E10_AUTHORIZE_PATH: &str = "/papi/sso/oauth2.0/authorize";
const E10_TOKEN_PATH: &str = "/papi/sso/oauth2.0/accessToken";
const E10_PROFILE_PATH: &str = "/papi/sso/oauth2.0/profile";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("OAuth origin must be an HTTPS origin (HTTP is allowed only on loopback)")]
    InvalidOrigin,
    #[error("client_id is required; register an OAuth application with the provider first")]
    MissingClient,
    #[error("OAuth state is missing or does not match; the callback was rejected")]
    InvalidState,
    #[error("the provider did not return the OAuth state; this callback cannot be verified")]
    StateNotReturned,
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
            Self::StateNotReturned => "state_not_returned",
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
    /// `browser` (authorization-code flows: open the authorize URL) or
    /// `device` (GitHub: show the user code and open the verification URL).
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
    /// Redacted display identity from the provider (login / username / UPN / email).
    pub account: String,
}

/// Secret-bearing E10 OAuth result. Intentionally neither Debug nor Serialize.
pub struct E10LoginResult {
    pub origin: String,
    pub agent_type: String,
    pub eteamsid: Zeroizing<String>,
    pub version: String,
    /// Verified by `e10::check_session` during completion.
    pub metadata: crate::e10::E10AccountMetadata,
}

/// Unified completion result across preset providers: bearer-token providers
/// and the E10 cookie session.
pub enum LoginOutcome {
    Tokens(OAuthResult),
    E10Session(E10LoginResult),
}

impl LoginOutcome {
    /// Redacted account summary safe for the management UI.
    pub fn account_summary(&self) -> String {
        match self {
            Self::Tokens(result) => result.account.clone(),
            Self::E10Session(result) => {
                let metadata = &result.metadata;
                if metadata.user_name.is_empty() {
                    metadata.user_id.clone()
                } else {
                    metadata.user_name.clone()
                }
            }
        }
    }
}

/// Map a connection host to a preset provider. This is the single source of
/// truth mirrored by `check.rs` and the desktop/frontend provider pickers.
pub fn infer_provider_for_host(host: &str) -> Option<&'static str> {
    let host = host.trim().to_ascii_lowercase();
    match host.as_str() {
        "api.github.com" => Some(PROVIDER_GITHUB),
        "gitlab.com" | "www.gitlab.com" => Some(PROVIDER_GITLAB),
        "gitee.com" | "www.gitee.com" => Some(PROVIDER_GITEE),
        "graph.microsoft.com" => Some(PROVIDER_MICROSOFT),
        "www.googleapis.com" => Some(PROVIDER_GOOGLE),
        other => {
            if other.ends_with(".gitlab.com") {
                Some(PROVIDER_GITLAB)
            } else if other.ends_with(".googleapis.com") {
                Some(PROVIDER_GOOGLE)
            } else {
                None
            }
        }
    }
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

/// Microsoft tenant slot: `organizations` / `consumers` / `common` or a
/// tenant identifier (GUID or friendly name). No path traversal.
fn valid_tenant(value: &str) -> Option<&str> {
    let value = value.trim();
    ((1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')))
        .then_some(value)
}

/// Mirrors the E10 agent-type validation in `e10.rs`.
fn valid_agent_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// HTTPS origin or loopback HTTP, mirroring Connection login rules.
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
// Authorization code + PKCE with a loopback callback listener.
// GitLab (JSON token body), Microsoft and Google (form token body) share it.
// ---------------------------------------------------------------------------

/// How the token endpoint accepts exchange/refresh bodies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenTransport {
    Json,
    Form,
}

/// Endpoint and parsing configuration for one preset provider.
struct AuthCodeConfig {
    provider: &'static str,
    authorize_endpoint: String,
    token_endpoint: String,
    identity_endpoint: String,
    /// JSON fields that may carry the redacted account name, tried in order.
    identity_fields: &'static [&'static str],
    pkce: bool,
    transport: TokenTransport,
    extra_authorize_params: Vec<(String, String)>,
    loopback_port: u16,
}

pub struct AuthorizationCodeFlow {
    info: OAuthStart,
    listener: TcpListener,
    state: Zeroizing<String>,
    verifier: Option<Zeroizing<String>>,
    redirect_uri: String,
    config: AuthCodeConfig,
    client_id: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}

/// GitLab keeps its historical name so existing call sites stay unchanged.
pub type GitLabOAuthFlow = AuthorizationCodeFlow;

impl AuthorizationCodeFlow {
    /// GitLab (gitlab.com and self-managed): `{origin}/oauth/*`, JSON token
    /// body, fixed loopback port 9867.
    pub fn begin(origin: &str, client_id: &str, scope: &str) -> Result<Self, OAuthError> {
        let origin = normalize_origin(origin)?;
        Self::start(
            AuthCodeConfig {
                provider: PROVIDER_GITLAB,
                authorize_endpoint: format!("{origin}/oauth/authorize"),
                token_endpoint: format!("{origin}/oauth/token"),
                identity_endpoint: format!("{origin}/api/v4/user"),
                identity_fields: &["username"],
                pkce: true,
                transport: TokenTransport::Json,
                extra_authorize_params: Vec::new(),
                loopback_port: GITLAB_LOOPBACK_PORT,
            },
            client_id,
            scope,
        )
    }

    /// Microsoft Entra ID public client: v2.0 endpoints under
    /// `login.microsoftonline.com/{tenant}`, form token body, Graph identity.
    pub fn microsoft(tenant: &str, client_id: &str, scope: &str) -> Result<Self, OAuthError> {
        Self::microsoft_at(
            "https://login.microsoftonline.com",
            "https://graph.microsoft.com",
            tenant,
            client_id,
            scope,
        )
    }

    /// Test seam: inject local authority/Graph bases.
    pub fn microsoft_at(
        authority: &str,
        graph: &str,
        tenant: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<Self, OAuthError> {
        let authority = normalize_origin(authority)?;
        let graph = normalize_origin(graph)?;
        let tenant = valid_tenant(tenant).ok_or(OAuthError::InvalidOrigin)?;
        Self::start(
            AuthCodeConfig {
                provider: PROVIDER_MICROSOFT,
                authorize_endpoint: format!("{authority}/{tenant}/oauth2/v2.0/authorize"),
                token_endpoint: format!("{authority}/{tenant}/oauth2/v2.0/token"),
                identity_endpoint: format!("{graph}/v1.0/me"),
                identity_fields: &["userPrincipalName"],
                pkce: true,
                transport: TokenTransport::Form,
                extra_authorize_params: Vec::new(),
                loopback_port: MICROSOFT_LOOPBACK_PORT,
            },
            client_id,
            scope,
        )
    }

    /// Google installed/desktop client: `access_type=offline` so a refresh
    /// token is issued on first consent; PKCE replaces the optional secret.
    pub fn google(client_id: &str, scope: &str) -> Result<Self, OAuthError> {
        Self::google_at(
            "https://accounts.google.com",
            "https://oauth2.googleapis.com",
            "https://openidconnect.googleapis.com",
            client_id,
            scope,
        )
    }

    /// Test seam: inject local authorize/token/identity bases.
    pub fn google_at(
        authorize_base: &str,
        token_base: &str,
        identity_base: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<Self, OAuthError> {
        let authorize_base = normalize_origin(authorize_base)?;
        let token_base = normalize_origin(token_base)?;
        let identity_base = normalize_origin(identity_base)?;
        Self::start(
            AuthCodeConfig {
                provider: PROVIDER_GOOGLE,
                authorize_endpoint: format!("{authorize_base}/o/oauth2/v2/auth"),
                token_endpoint: format!("{token_base}/token"),
                identity_endpoint: format!("{identity_base}/v1/userinfo"),
                identity_fields: &["email", "sub"],
                pkce: true,
                transport: TokenTransport::Form,
                extra_authorize_params: vec![("access_type".into(), "offline".into())],
                loopback_port: GOOGLE_LOOPBACK_PORT,
            },
            client_id,
            scope,
        )
    }

    fn start(config: AuthCodeConfig, client_id: &str, scope: &str) -> Result<Self, OAuthError> {
        if !valid_client_id(client_id) {
            return Err(OAuthError::MissingClient);
        }
        let listener = TcpListener::bind(("127.0.0.1", config.loopback_port))
            .map_err(|_| OAuthError::PortUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| OAuthError::Network)?;
        let redirect_uri =
            format!("http://127.0.0.1:{}{OAUTH_REDIRECT_PATH}", config.loopback_port);
        let state = Zeroizing::new(random_token());
        let verifier = config
            .pkce
            .then(|| Zeroizing::new(random_token()));
        let mut url =
            Url::parse(&config.authorize_endpoint).map_err(|_| OAuthError::InvalidOrigin)?;
        {
            let mut params = url.query_pairs_mut();
            params
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code");
            if !scope.trim().is_empty() {
                params.append_pair("scope", scope.trim());
            }
            for (name, value) in &config.extra_authorize_params {
                params.append_pair(name, value);
            }
            params.append_pair("state", state.as_str());
            if let Some(verifier) = verifier.as_ref() {
                params.append_pair("code_challenge_method", "S256");
                params.append_pair(
                    "code_challenge",
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(Sha256::digest(verifier.as_bytes())),
                );
            }
        }
        let origin = Url::parse(&config.authorize_endpoint)
            .map(|url| url.origin().ascii_serialization())
            .map_err(|_| OAuthError::InvalidOrigin)?;
        Ok(Self {
            info: OAuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                provider: config.provider.to_owned(),
                kind: "browser".into(),
                url: url.to_string(),
                user_code: None,
                expires_at: (chrono::Utc::now() + chrono::Duration::seconds(AUTH_LIFETIME_SECONDS))
                    .to_rfc3339(),
                origin,
            },
            listener,
            state,
            verifier,
            redirect_uri,
            config,
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
            let exchange = exchange_code(
                &self.config,
                &self.client_id,
                &self.redirect_uri,
                &code,
                self.verifier.as_ref().map(|verifier| verifier.as_str()),
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

fn exchange_code(
    config: &AuthCodeConfig,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: Option<&str>,
) -> Result<OAuthResult, OAuthError> {
    let tokens = match config.transport {
        TokenTransport::Json => {
            let mut body = json!({
                "client_id": client_id,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            });
            if let Some(verifier) = verifier {
                body["code_verifier"] = json!(verifier);
            }
            token_request(&config.token_endpoint, &body.to_string())?
        }
        TokenTransport::Form => {
            let mut pairs: Vec<(&str, String)> = vec![
                ("grant_type", "authorization_code".into()),
                ("code", code.to_owned()),
                ("redirect_uri", redirect_uri.to_owned()),
                ("client_id", client_id.to_owned()),
            ];
            if let Some(verifier) = verifier {
                pairs.push(("code_verifier", verifier.to_owned()));
            }
            token_request_form(&config.token_endpoint, &form_body(&pairs))?
        }
    };
    let identity = fetch_json(&config.identity_endpoint, tokens.access_token.as_str())?;
    let account = config
        .identity_fields
        .iter()
        .find_map(|field| {
            identity
                .get(*field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
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
        Self::begin_at(
            "https://api.github.com",
            "https://github.com",
            client_id,
            scope,
        )
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
        let expires_in = response
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(900);
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
                let identity = fetch_json(&self.identity_endpoint, access_token.as_str())?;
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
// E10: platform-private authorization code. No client id, no secret, no
// PKCE. pman always sends a state and refuses stateless callbacks with
// `StateNotReturned` so the desktop can fall back to the WebView2 login.
// ---------------------------------------------------------------------------

pub struct E10OAuthFlow {
    info: OAuthStart,
    listener: TcpListener,
    state: Zeroizing<String>,
    redirect_uri: String,
    origin: String,
    agent_type: String,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}

impl E10OAuthFlow {
    pub fn begin(origin: &str, agent_type: &str) -> Result<Self, OAuthError> {
        let origin = normalize_origin(origin)?;
        if !valid_agent_type(agent_type) {
            return Err(OAuthError::InvalidResponse);
        }
        let listener = TcpListener::bind(("127.0.0.1", E10_LOOPBACK_PORT))
            .map_err(|_| OAuthError::PortUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| OAuthError::Network)?;
        let redirect_uri = format!("http://127.0.0.1:{E10_LOOPBACK_PORT}{OAUTH_REDIRECT_PATH}");
        let state = Zeroizing::new(random_token());
        let mut url =
            Url::parse(&format!("{origin}{E10_AUTHORIZE_PATH}")).map_err(|_| OAuthError::InvalidOrigin)?;
        {
            let mut params = url.query_pairs_mut();
            params
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("access_type", "agent")
                .append_pair("agent_type", agent_type)
                .append_pair("state", state.as_str());
        }
        Ok(Self {
            info: OAuthStart {
                session_id: uuid::Uuid::new_v4().to_string(),
                provider: PROVIDER_E10.into(),
                kind: "browser".into(),
                url: url.to_string(),
                user_code: None,
                expires_at: (chrono::Utc::now() + chrono::Duration::seconds(AUTH_LIFETIME_SECONDS))
                    .to_rfc3339(),
                origin: origin.clone(),
            },
            listener,
            state,
            redirect_uri,
            origin,
            agent_type: agent_type.to_owned(),
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

    /// Consumes the flow. A callback without a `state` parameter means the
    /// platform did not echo pman's state (the e10-login CLI never sends
    /// one); that callback is never trusted — `StateNotReturned` tells the
    /// desktop to fall back to the isolated WebView2 login instead.
    pub fn complete(self, timeout: Duration) -> Result<E10LoginResult, OAuthError> {
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
            if state.is_empty() {
                reply(&mut stream, false);
                return Err(OAuthError::StateNotReturned);
            }
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
            let exchange =
                exchange_e10_session(&self.origin, &code, &self.redirect_uri, &self.agent_type);
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

/// First non-empty string among the candidate field names.
fn e10_field(value: &Value, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| {
            value
                .get(*name)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn e10_error_to_oauth(error: crate::e10::E10Error) -> OAuthError {
    match error {
        crate::e10::E10Error::Network => OAuthError::Network,
        crate::e10::E10Error::AccountMismatch => OAuthError::AccountMismatch,
        _ => OAuthError::InvalidResponse,
    }
}

fn exchange_e10_session(
    origin: &str,
    code: &str,
    redirect_uri: &str,
    agent_type: &str,
) -> Result<E10LoginResult, OAuthError> {
    let body = form_body(&[
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", redirect_uri.to_owned()),
    ]);
    let value = post_form(&format!("{origin}{E10_TOKEN_PATH}"), &body)?;
    let access = e10_field(&value, &["access_token", "accessToken"]);
    let mut eteamsid = e10_field(&value, &["eteamsId", "eteamsid"]);
    let mut version = e10_field(&value, &["version", "baselineVersion"]);
    if eteamsid.is_empty() && !access.is_empty() {
        // e10-login's profile fallback for environments that do not put the
        // session id in the token response.
        let profile = post_form(
            &format!("{origin}{E10_PROFILE_PATH}?access_token={}", urlencode(&access)),
            "",
        )?;
        if eteamsid.is_empty() {
            eteamsid = e10_field(&profile, &["eteamsId", "eteamsid"]);
        }
        if version.is_empty() {
            version = e10_field(&profile, &["version", "baselineVersion"]);
        }
    }
    if eteamsid.is_empty() || eteamsid.len() > 4096 {
        return Err(OAuthError::InvalidResponse);
    }
    let host = Url::parse(origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or(OAuthError::InvalidOrigin)?;
    let secret = json!({
        "origin": origin,
        "provider": PROVIDER_E10,
        "agent_type": agent_type,
        "cookies": [{
            "name": "ETEAMSID",
            "value": eteamsid,
            "domain": host,
            "path": "/",
            "host_only": true
        }]
    });
    let metadata = crate::e10::check_session(origin, &secret).map_err(e10_error_to_oauth)?;
    Ok(E10LoginResult {
        origin: origin.to_owned(),
        agent_type: agent_type.to_owned(),
        eteamsid: Zeroizing::new(eteamsid),
        version,
        metadata,
    })
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

pub fn refresh_microsoft_tokens(
    tenant: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, OAuthError> {
    refresh_microsoft_tokens_at("https://login.microsoftonline.com", tenant, client_id, refresh_token)
}

/// Test seam: inject a local authority base.
pub fn refresh_microsoft_tokens_at(
    authority: &str,
    tenant: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, OAuthError> {
    let authority = normalize_origin(authority)?;
    let tenant = valid_tenant(tenant).ok_or(OAuthError::InvalidOrigin)?;
    if !valid_client_id(client_id) {
        return Err(OAuthError::MissingClient);
    }
    // Public client refresh: client_id + refresh_token, no secret
    // ("required for web apps" only per the v2.0 protocol reference).
    let body = form_body(&[
        ("grant_type", "refresh_token".to_owned()),
        ("client_id", client_id.to_owned()),
        ("refresh_token", refresh_token.to_owned()),
    ]);
    token_request_form(&format!("{authority}/{tenant}/oauth2/v2.0/token"), &body)
}

pub fn refresh_google_tokens(
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, OAuthError> {
    refresh_google_tokens_at("https://oauth2.googleapis.com", client_id, refresh_token)
}

/// Test seam: inject a local token base.
pub fn refresh_google_tokens_at(
    token_base: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, OAuthError> {
    let token_base = normalize_origin(token_base)?;
    if !valid_client_id(client_id) {
        return Err(OAuthError::MissingClient);
    }
    // The optional client_secret is deliberately omitted for installed apps.
    let body = form_body(&[
        ("grant_type", "refresh_token".to_owned()),
        ("client_id", client_id.to_owned()),
        ("refresh_token", refresh_token.to_owned()),
    ]);
    token_request_form(&format!("{token_base}/token"), &body)
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
        if let Some(object) = extra.as_object_mut() {
            object.remove("oauth_pending");
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
    /// Every provider branch is explicit; unknown or token-only providers are
    /// rejected before any network request.
    pub fn refresh_connection_tokens(
        &mut self,
        alias: &str,
        expected_origin: Option<&str>,
    ) -> Result<String, VaultError> {
        self.ensure_unlocked()?;
        let material = self.get_site_secret(alias)?;
        if material.get("auth_profile").is_some() {
            let site = self.list_sites()?.into_iter().find(|s| s.alias == alias).ok_or_else(||VaultError::UnknownSite(alias.into()))?;
            let updated = crate::authflow::refresh_session(&site.site_url, &material).map_err(|e|VaultError::InvalidSchema(e.to_string()))?;
            self.update_secret(alias, updated)?;
            return Ok("连接凭据已刷新".into());
        }

        let site = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        let details = self.details(alias)?;
        let provider = match details.provider.as_deref() {
            Some(provider) => provider.to_owned(),
            None => url::Url::parse(&site.site_url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
                .and_then(|host| infer_provider_for_host(&host).map(str::to_owned))
                .ok_or_else(|| {
                    VaultError::InvalidSchema(
                        "oauth_unsupported: 未识别此连接的 OAuth 提供方；请在连接详情选择提供方"
                            .into(),
                    )
                })?,
        };
        match provider.as_str() {
            PROVIDER_E10 => {
                return Err(VaultError::InvalidSchema(
                    "E10 会话不支持自动刷新，请重新登录".into(),
                ))
            }
            PROVIDER_GITEE => {
                return Err(VaultError::InvalidSchema(
                    "Gitee 使用私人令牌接入，不支持自动刷新；请在 Gitee 重新生成令牌后更新"
                        .into(),
                ))
            }
            PROVIDER_GITHUB | PROVIDER_GITLAB | PROVIDER_MICROSOFT | PROVIDER_GOOGLE => {}
            other => {
                return Err(VaultError::InvalidSchema(format!(
                    "oauth_unsupported: 提供方 {other} 没有受支持的刷新流程"
                )))
            }
        }
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
            PROVIDER_GITLAB => refresh_gitlab_tokens(
                expected_origin.unwrap_or(&site.site_url),
                &client_id,
                &refresh_token,
                &format!("http://127.0.0.1:{GITLAB_LOOPBACK_PORT}{OAUTH_REDIRECT_PATH}"),
            )
            .map_err(|error| VaultError::InvalidSchema(error.to_string()))?,
            PROVIDER_MICROSOFT => {
                let tenant = details
                    .oauth_tenant
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("organizations");
                refresh_microsoft_tokens(tenant, &client_id, &refresh_token)
                    .map_err(|error| VaultError::InvalidSchema(error.to_string()))?
            }
            PROVIDER_GOOGLE => refresh_google_tokens(&client_id, &refresh_token)
                .map_err(|error| VaultError::InvalidSchema(error.to_string()))?,
            _ => unreachable!("provider branches were validated above"),
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

fn parse_token_response(status: u16, value: Value) -> Result<OAuthTokens, OAuthError> {
    if !(200..299).contains(&status) {
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
        expires_at: value
            .get("expires_in")
            .and_then(Value::as_i64)
            .map(|seconds| (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339()),
        scope: value
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

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
    let status = response.status().as_u16();
    let bytes: Vec<u8> = response.bytes().map_err(|_| OAuthError::Network)?.to_vec();
    if bytes.len() > 512 * 1024 {
        return Err(OAuthError::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)?;
    parse_token_response(status, value)
}

fn token_request_form(endpoint: &str, form_body: &str) -> Result<OAuthTokens, OAuthError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| OAuthError::Network)?;
    let response = client
        .post(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body.to_owned())
        .send()
        .map_err(|_| OAuthError::Network)?;
    let status = response.status().as_u16();
    let bytes: Vec<u8> = response.bytes().map_err(|_| OAuthError::Network)?.to_vec();
    if bytes.len() > 512 * 1024 {
        return Err(OAuthError::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)?;
    parse_token_response(status, value)
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
    let bytes: Vec<u8> = response.bytes().map_err(|_| OAuthError::Network)?.to_vec();
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
    let bytes: Vec<u8> = response.bytes().map_err(|_| OAuthError::Network)?.to_vec();
    if bytes.len() > 512 * 1024 {
        return Err(OAuthError::InvalidResponse);
    }
    // Some E10 gateways prepend a UTF-8 BOM before the JSON body.
    let bytes = bytes
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(&bytes);
    serde_json::from_slice(bytes).map_err(|_| OAuthError::InvalidResponse)
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn form_body(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", urlencode(name), urlencode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn read_callback(stream: &mut TcpStream, redirect_uri: &str) -> Result<Option<String>, OAuthError> {
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
        .trim_end_matches(OAUTH_REDIRECT_PATH)
        .trim_end_matches('/');
    if !target.starts_with(OAUTH_REDIRECT_PATH)
        && !target.starts_with(&format!("{prefix}{OAUTH_REDIRECT_PATH}"))
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
    const SECRET_ETEAMSID: &str = "SYNTHETIC_ETEAMSID_NEVER_OUTPUT_33619";

    /// Every browser flow binds a fixed loopback port; tests using the same
    /// port must not run concurrently with each other.
    static PORT_LOCK: Mutex<()> = Mutex::new(());
    static MS_PORT_LOCK: Mutex<()> = Mutex::new(());
    static GOOGLE_PORT_LOCK: Mutex<()> = Mutex::new(());
    static E10_PORT_LOCK: Mutex<()> = Mutex::new(());

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
                    // Accept remains nonblocking for shutdown; each request
                    // must wait for body fragments on the accepted socket.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 8192];
                    loop {
                        let size = match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(size) => size,
                        };
                        bytes.extend_from_slice(&buffer[..size]);
                        if let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&bytes[..header_end]);
                            let content_length = headers
                                .lines()
                                .filter_map(|line| line.split_once(':'))
                                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if bytes.len() >= header_end + 4 + content_length {
                                break;
                            }
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

    #[test]
    fn fake_provider_waits_for_fragmented_request_bodies() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let provider = FakeProvider::start(move |request| {
            sender.send(request.clone()).unwrap();
            FakeProvider::json_response(json!({"ok": true}))
        });
        let body = "client_id=fixture&scope=repo";
        let mut stream = TcpStream::connect(&provider.address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(
            stream,
            "POST /token HTTP/1.1\r\nHost: localhost\r\ncOnTeNt-LeNgTh: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        let middle = body.len() / 2;
        stream.write_all(&body.as_bytes()[..middle]).unwrap();
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        stream.write_all(&body.as_bytes()[middle..]).unwrap();
        let request = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(request, ("/token".to_owned(), body.to_owned()));
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
    }

    fn query_param(url: &str, name: &str) -> String {
        Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .unwrap_or_default()
    }

    fn send_callback_at(port: u16, target: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        Ok(response)
    }

    fn send_callback(target: &str) -> std::io::Result<String> {
        send_callback_at(GITLAB_LOOPBACK_PORT, target)
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let flow = GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
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
        let response = send_callback(&format!("/callback?code=test-code&state={state}")).unwrap();
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
        let flow = GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
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
        let flow = GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
        let state = query_param(&flow.info().url, "state");
        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        // A spec-compliant error redirect still carries the state parameter.
        send_callback(&format!(
            "/callback?error=access_denied&error_description=no&state={state}"
        ))
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
        let flow = GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
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
        let flow = GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let flow = GitLabOAuthFlow::begin(&provider.base(), "client-id-1", "read_user").unwrap();
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
        assert!(
            done.lock().unwrap().take().unwrap(),
            "first callback completes"
        );
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
        vault
            .finish_oauth_login("gitlab", "gitlab", &result)
            .unwrap();
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "gitlab",
                &provider.base(),
                "api_token",
                json!({"token": SECRET_TOKEN, "oauth_refresh_token": SECRET_REFRESH}),
            ))
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
                        body.contains(
                            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
                        ),
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
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
        assert!(
            *polls.lock().unwrap() >= 3,
            "should have polled pending+slow_down+success"
        );
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
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
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
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

    // -----------------------------------------------------------------
    // Microsoft: authorization code + PKCE, form transport, no secret.
    // -----------------------------------------------------------------

    #[test]
    fn microsoft_flow_uses_pkce_form_exchange_and_fetches_identity() {
        let _port = MS_PORT_LOCK.lock().unwrap();
        let challenge: std::sync::Arc<Mutex<String>> = Default::default();
        let server_challenge = challenge.clone();
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/organizations/oauth2/v2.0/token" {
                assert!(
                    body.contains("grant_type=authorization_code"),
                    "{body}"
                );
                assert!(body.contains("code=ms-code"));
                assert!(body.contains("client_id=client-ms-1"));
                let verifier = body
                    .split('&')
                    .find_map(|pair| {
                        pair.split_once('=')
                            .filter(|(key, _)| *key == "code_verifier")
                            .map(|(_, value)| value.to_owned())
                    })
                    .expect("code_verifier must be present");
                let verifier = url::form_urlencoded::parse(format!("v={verifier}").as_bytes())
                    .next()
                    .map(|(_, value)| value.to_string())
                    .unwrap_or_default();
                let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(verifier.as_bytes()));
                assert_eq!(
                    digest,
                    server_challenge.lock().unwrap().as_str(),
                    "PKCE verifier must match the authorize challenge"
                );
                assert!(
                    !body.contains("client_secret="),
                    "public client exchange must not send a secret"
                );
                FakeProvider::json_response(json!({
                    "access_token": SECRET_TOKEN,
                    "refresh_token": SECRET_REFRESH,
                    "expires_in": 3599,
                    "scope": "User.Read offline_access"
                }))
            } else if path == "/v1.0/me" {
                FakeProvider::json_response(json!({
                    "userPrincipalName": "dev@corp.example",
                    "id": "11111111-2222-3333-4444-555555555555"
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let base = provider.base();
        let flow = AuthorizationCodeFlow::microsoft_at(
            &base,
            &base,
            "organizations",
            "client-ms-1",
            "User.Read offline_access",
        )
        .unwrap();
        let info = flow.info();
        assert_eq!(info.provider, "microsoft");
        assert!(info.url.contains("/organizations/oauth2/v2.0/authorize"), "{}", info.url);
        assert_eq!(query_param(&info.url, "code_challenge_method"), "S256");
        assert_eq!(query_param(&info.url, "response_type"), "code");
        *challenge.lock().unwrap() = query_param(&info.url, "code_challenge");

        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        let state = query_param(&info.url, "state");
        send_callback_at(MICROSOFT_LOOPBACK_PORT, &format!("/callback?code=ms-code&state={state}"))
            .unwrap();
        handle.join().unwrap();
        let result = done.lock().unwrap().take().expect("flow finished");
        let result = result.expect("microsoft flow should succeed");
        assert_eq!(result.account, "dev@corp.example");
        assert_eq!(result.access_token.as_str(), SECRET_TOKEN);
        assert_eq!(
            result.refresh_token.as_ref().unwrap().as_str(),
            SECRET_REFRESH
        );
    }

    #[test]
    fn microsoft_refresh_uses_form_without_secret_and_rotates() {
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/common/oauth2/v2.0/token" {
                assert!(body.contains("grant_type=refresh_token"), "{body}");
                assert!(body.contains("client_id=client-ms-1"));
                assert!(body.contains(&format!("refresh_token={}", SECRET_REFRESH)));
                assert!(!body.contains("client_secret="));
                FakeProvider::json_response(json!({
                    "access_token": "MS_ROTATED_ACCESS_000001",
                    "refresh_token": "MS_ROTATED_REFRESH_000001",
                    "expires_in": 3599
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let tokens =
            refresh_microsoft_tokens_at(&provider.base(), "common", "client-ms-1", SECRET_REFRESH)
                .unwrap();
        assert_eq!(tokens.access_token.as_str(), "MS_ROTATED_ACCESS_000001");
        assert_eq!(
            tokens.refresh_token.as_ref().unwrap().as_str(),
            "MS_ROTATED_REFRESH_000001"
        );
    }

    // -----------------------------------------------------------------
    // Google: authorization code + PKCE with access_type=offline.
    // -----------------------------------------------------------------

    #[test]
    fn google_flow_requests_offline_access_and_verifies_identity() {
        let _port = GOOGLE_PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/token" {
                assert!(body.contains("grant_type=authorization_code"), "{body}");
                assert!(body.contains("code=g-code"));
                assert!(body.contains("code_verifier="));
                assert!(!body.contains("client_secret="));
                FakeProvider::json_response(json!({
                    "access_token": SECRET_TOKEN,
                    "expires_in": 3599,
                    "scope": "openid email profile"
                }))
            } else if path == "/v1/userinfo" {
                FakeProvider::json_response(json!({
                    "sub": "1234567890",
                    "email": "user@example.test",
                    "email_verified": true
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let base = provider.base();
        let flow =
            AuthorizationCodeFlow::google_at(&base, &base, &base, "client-g-1", "openid email profile")
                .unwrap();
        let info = flow.info();
        assert_eq!(info.provider, "google");
        assert_eq!(query_param(&info.url, "access_type"), "offline");
        assert_eq!(query_param(&info.url, "code_challenge_method"), "S256");

        let done: std::sync::Arc<Mutex<Option<Result<OAuthResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        let state = query_param(&info.url, "state");
        send_callback_at(GOOGLE_LOOPBACK_PORT, &format!("/callback?code=g-code&state={state}"))
            .unwrap();
        handle.join().unwrap();
        let result = done.lock().unwrap().take().expect("flow finished");
        let result = result.expect("google flow should succeed");
        assert_eq!(result.account, "user@example.test");
        // No refresh_token on this consent (Google only issues it on first
        // consent with access_type=offline).
        assert!(result.refresh_token.is_none());
    }

    #[test]
    fn google_refresh_omits_secret_and_rotates_tokens() {
        let provider = FakeProvider::start(move |(path, body)| {
            if path == "/token" {
                assert!(body.contains("grant_type=refresh_token"), "{body}");
                assert!(body.contains("client_id=client-g-1"));
                assert!(!body.contains("client_secret="));
                FakeProvider::json_response(json!({
                    "access_token": "G_ROTATED_ACCESS_000001",
                    "expires_in": 3599,
                    "scope": "openid email profile"
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let tokens =
            refresh_google_tokens_at(&provider.base(), "client-g-1", SECRET_REFRESH).unwrap();
        assert_eq!(tokens.access_token.as_str(), "G_ROTATED_ACCESS_000001");
    }

    #[test]
    fn google_without_refresh_token_errors_before_any_network() {
        let provider = FakeProvider::start(move |_request| {
            panic!("a connection without a refresh token must not touch the network")
        });
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "google",
                "https://www.googleapis.com",
                "api_token",
                json!({"token": SECRET_TOKEN, "provider": "google"}),
            ))
            .unwrap();
        vault
            .update_details(
                "google",
                json!({"provider": "google", "oauth_client_id": "client-g-1"}),
            )
            .unwrap();
        let _guard = &provider;
        let error = vault.refresh_connection_tokens("google", None).unwrap_err();
        assert!(error.to_string().contains("没有可刷新"), "{error}");
        assert!(provider.paths().is_empty());
    }

    #[test]
    fn refresh_rejects_unknown_or_token_only_providers_without_network() {
        let provider = FakeProvider::start(move |_request| {
            panic!("gitee/unknown providers must never reach a token endpoint")
        });
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        for alias in ["gitee-site", "odd-site"] {
            vault
                .add_site(crate::SiteInput::new(
                    alias,
                    "https://gitee.com",
                    "api_token",
                    json!({"token": SECRET_TOKEN, "oauth_refresh_token": SECRET_REFRESH}),
                ))
                .unwrap();
            vault
                .update_details(
                    alias,
                    json!({
                        "provider": if alias == "gitee-site" { "gitee" } else { "private-portal" },
                        "oauth_client_id": "client-x"
                    }),
                )
                .unwrap();
        }
        let _guard = &provider;
        let error = vault
            .refresh_connection_tokens("gitee-site", None)
            .unwrap_err();
        assert!(error.to_string().contains("Gitee"), "{error}");
        let error = vault.refresh_connection_tokens("odd-site", None).unwrap_err();
        assert!(error.to_string().contains("oauth_unsupported"), "{error}");
        assert!(provider.paths().is_empty());
    }

    // -----------------------------------------------------------------
    // E10: platform-private authorization code with strict state checks.
    // -----------------------------------------------------------------

    #[test]
    fn e10_flow_success_binds_state_and_session_identity() {
        let _port = E10_PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, body)| {
            if path.starts_with(E10_TOKEN_PATH) {
                assert!(body.contains("grant_type=authorization_code"), "{body}");
                assert!(body.contains("code=e10-code"));
                assert!(body.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A19800%2Fcallback"));
                assert!(!body.contains("client_secret="));
                FakeProvider::json_response(json!({
                    "access_token": SECRET_TOKEN,
                    "eteamsId": SECRET_ETEAMSID,
                    "id": "77",
                    "agentType": "Codex",
                    "version": "25.06"
                }))
            } else if path.starts_with("/api/baseserver/layout/teamsCheck") {
                FakeProvider::json_response(json!({
                    "currentUser": {"employeeId": "77", "userName": "张三"},
                    "currentTenant": {"tenantKey": "tk-1", "tenantName": "示例租户"}
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let flow = E10OAuthFlow::begin(&provider.base(), "Codex").unwrap();
        let info = flow.info();
        assert_eq!(info.provider, "e10");
        assert!(info.url.contains(E10_AUTHORIZE_PATH), "{}", info.url);
        assert_eq!(query_param(&info.url, "access_type"), "agent");
        assert_eq!(query_param(&info.url, "agent_type"), "Codex");
        assert!(!query_param(&info.url, "state").is_empty());

        let done: std::sync::Arc<Mutex<Option<Result<E10LoginResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        let state = query_param(&info.url, "state");
        send_callback_at(E10_LOOPBACK_PORT, &format!("/callback?code=e10-code&state={state}"))
            .unwrap();
        handle.join().unwrap();
        let result = done.lock().unwrap().take().expect("flow finished");
        let result = result.expect("e10 flow should succeed");
        assert_eq!(result.eteamsid.as_str(), SECRET_ETEAMSID);
        assert_eq!(result.agent_type, "Codex");
        assert_eq!(result.version, "25.06");
        assert_eq!(result.metadata.user_id, "77");
        assert!(result.metadata.account_id.starts_with("account-"));
        assert_eq!(result.metadata.tenant_key, "tk-1");
    }

    #[test]
    fn e10_callback_without_state_reports_state_not_returned_and_never_exchanges() {
        let _port = E10_PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, _)| {
            if path.starts_with("/papi/") {
                panic!("a stateless callback must never be exchanged");
            }
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let flow = E10OAuthFlow::begin(&provider.base(), "Codex").unwrap();
        let done: std::sync::Arc<Mutex<Option<Result<E10LoginResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        // The e10-login CLI never sends state, so the platform may redirect
        // without one. pman refuses instead of skipping validation.
        send_callback_at(E10_LOOPBACK_PORT, "/callback?code=e10-code").unwrap();
        handle.join().unwrap();
        let outcome = done.lock().unwrap().take().expect("flow finished");
        assert!(matches!(outcome, Err(OAuthError::StateNotReturned)));
        assert!(
            !provider.paths().iter().any(|path| path.starts_with("/papi/")),
            "无 state 的回调不得触发任何平台请求"
        );
    }

    #[test]
    fn e10_forged_state_is_rejected_as_invalid() {
        let _port = E10_PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, _)| {
            if path.starts_with("/papi/") {
                panic!("a forged state must never be exchanged");
            }
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let flow = E10OAuthFlow::begin(&provider.base(), "Codex").unwrap();
        let done: std::sync::Arc<Mutex<Option<Result<E10LoginResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        send_callback_at(
            E10_LOOPBACK_PORT,
            "/callback?code=e10-code&state=forged-state",
        )
        .unwrap();
        handle.join().unwrap();
        let outcome = done.lock().unwrap().take().expect("flow finished");
        assert!(matches!(outcome, Err(OAuthError::InvalidState)));
    }

    #[test]
    fn e10_flow_falls_back_to_profile_endpoint_for_eteamsid() {
        let _port = E10_PORT_LOCK.lock().unwrap();
        let provider = FakeProvider::start(move |(path, _body)| {
            if path.starts_with(E10_TOKEN_PATH) {
                // This environment does not put eteamsId in the token body.
                FakeProvider::json_response(json!({"access_token": SECRET_TOKEN}))
            } else if path.starts_with(E10_PROFILE_PATH) {
                FakeProvider::json_response(json!({
                    "eteamsId": SECRET_ETEAMSID,
                    "id": "88",
                    "version": "25.06"
                }))
            } else if path.starts_with("/api/baseserver/layout/teamsCheck") {
                FakeProvider::json_response(json!({
                    "currentUser": {"employeeId": "88"},
                    "currentTenant": {"tenantKey": "tk-2"}
                }))
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        });
        let flow = E10OAuthFlow::begin(&provider.base(), "WorkBuddy").unwrap();
        let state = query_param(&flow.info().url, "state");
        let done: std::sync::Arc<Mutex<Option<Result<E10LoginResult, OAuthError>>>> =
            Default::default();
        let worker = done.clone();
        let handle = std::thread::spawn(move || {
            let outcome = flow.complete(Duration::from_secs(10));
            *worker.lock().unwrap() = Some(outcome);
        });
        send_callback_at(E10_LOOPBACK_PORT, &format!("/callback?code=e10-code&state={state}"))
            .unwrap();
        handle.join().unwrap();
        let result = done.lock().unwrap().take().expect("flow finished");
        let result = result.expect("profile fallback should succeed");
        assert_eq!(result.eteamsid.as_str(), SECRET_ETEAMSID);
        assert_eq!(result.metadata.user_id, "88");
    }
}
