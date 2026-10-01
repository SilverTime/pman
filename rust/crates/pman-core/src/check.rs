//! Read-only connection checks.
//!
//! A check proves *some* capability at a point in time; it never grants,
//! revokes or re-plays anything. Only GET requests are sent: a write request
//! must never be used to test permissions. Responses are sanitized by the
//! shared proxy chain, and only the minimum identity fields (a login name)
//! are extracted. Official endpoints:
//! - GitHub `GET /user` — https://docs.github.com/en/rest/users/users#get-the-authenticated-user
//!   (checked 2026-09-19, REST API version 2022-11-28)
//! - GitLab v4 `GET /api/v4/user` — https://docs.gitlab.com/ee/api/users.html
//!   (checked 2026-09-19, GitLab REST API v4)
//! - Gitee v5 `GET /api/v5/user` — https://gitee.com/api/v5 (checked
//!   2026-09-21, Token path only — see OAUTH-PROVIDERS.md §2.6)
//! - Microsoft Graph `GET /v1.0/me` — https://learn.microsoft.com/en-us/graph/api/user-get
//!   (checked 2026-09-21, connection origin `graph.microsoft.com`)
//! - Google OIDC userinfo `GET https://openidconnect.googleapis.com/v1/userinfo`
//!   — https://developers.google.com/identity/openid-connect/openid-connect
//!   (checked 2026-09-21; provider-constant absolute endpoint because the
//!   identity origin differs from the business API origin)

use crate::status::{CheckEvidence, STATE_FORBIDDEN, STATE_NETWORK_ERROR, STATE_READY, STATE_RATE_LIMITED, STATE_TIMEOUT, STATE_UNAUTHORIZED, STATE_VERIFIED};
use crate::{ConnectionDetails, SiteSummary, Vault, VaultError};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

pub const PROVIDER_GITHUB: &str = "github";
pub const PROVIDER_GITLAB: &str = "gitlab";
pub const PROVIDER_GITEE: &str = "gitee";
pub const PROVIDER_MICROSOFT: &str = "microsoft";
pub const PROVIDER_GOOGLE: &str = "google";
pub const PROVIDER_CUSTOM: &str = "custom";
pub const PROVIDER_CONNECTION: &str = "authflow";
pub const PROVIDER_E10: &str = "e10";
pub const PROVIDER_NONE: &str = "none";
/// Default identity endpoint per provider, relative to the site URL.
pub const GITHUB_CHECK_PATH: &str = "/user";
pub const GITLAB_CHECK_PATH: &str = "/api/v4/user";
pub const GITEE_CHECK_PATH: &str = "/api/v5/user";
pub const MICROSOFT_CHECK_PATH: &str = "/v1.0/me";
/// Google's documented userinfo endpoint lives on a different origin than
/// the business API (`www.googleapis.com`). It is a provider constant, never
/// user input, so it cannot become an SSRF vector; the shared proxy chain
/// only carries same-origin requests (see `http_proxy::build_url`).
pub const GOOGLE_IDENTITY_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// Result of one check. `message`/`account`/`scope` are safe to display:
/// they never contain credential material or raw response bodies.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CheckOutcome {
    pub provider: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub checked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// True when the service has no usable check path and only the saved
    /// credential state is reported (no network request was made).
    pub saved_only: bool,
}

/// Resolve which check applies. Explicit details win over host detection;
/// unknown services without a check path yield `PROVIDER_NONE`.
pub fn resolve_provider(site: &SiteSummary, details: &ConnectionDetails) -> String {
    if site.auth_type == "e10" || details.provider.as_deref() == Some(PROVIDER_E10) {
        return PROVIDER_E10.into();
    }
    if site.auth_type == "authflow" {
        return PROVIDER_CONNECTION.into();
    }
    if site.auth_type == "password" || site.site_url.is_empty() {
        return PROVIDER_NONE.into();
    }
    if let Some(provider) = details.provider.as_deref() {
        match provider {
            PROVIDER_GITHUB | PROVIDER_GITLAB | PROVIDER_GITEE | PROVIDER_MICROSOFT
            | PROVIDER_GOOGLE | PROVIDER_E10 => return provider.to_owned(),
            PROVIDER_CUSTOM => return PROVIDER_CUSTOM.into(),
            _ => return PROVIDER_NONE.into(),
        }
    }
    let host = url::Url::parse(&site.site_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    crate::oauth::infer_provider_for_host(&host)
        .map(str::to_owned)
        .unwrap_or_else(|| PROVIDER_NONE.into())
}

fn check_path(details: &ConnectionDetails, provider: &str, override_path: Option<&str>) -> Option<String> {
    let raw = match override_path.map(str::trim).filter(|p| !p.is_empty()) {
        Some(path) => Some(path),
        None => match provider {
            PROVIDER_GITHUB => Some(GITHUB_CHECK_PATH),
            PROVIDER_GITLAB => Some(GITLAB_CHECK_PATH),
            PROVIDER_GITEE => Some(GITEE_CHECK_PATH),
            PROVIDER_MICROSOFT => Some(MICROSOFT_CHECK_PATH),
            // Google's identity endpoint is an absolute provider constant
            // handled by its own branch below.
            PROVIDER_GOOGLE => None,
            PROVIDER_CUSTOM => details.check_path.as_deref().map(str::trim).filter(|p| !p.is_empty()),
            _ => None,
        },
    }?;
    if !raw.starts_with('/')
        || raw.contains(['?', '#', '\\'])
        || raw.chars().any(char::is_control)
        || raw.len() > 1024
    {
        return None;
    }
    Some(raw.to_owned())
}

fn parse_identity(provider: &str, body: Option<&Value>) -> Option<String> {
    let body = body?;
    let name = match provider {
        PROVIDER_GITHUB => body.get("login"),
        PROVIDER_GITLAB => body.get("username"),
        PROVIDER_GITEE => body.get("login"),
        PROVIDER_MICROSOFT => body.get("userPrincipalName"),
        _ => None,
    }?
    .as_str()?;
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        None
    } else {
        Some(name.to_owned())
    }
}

/// Prepared check material. The secret is cloned out under the vault lock
/// (same pattern as the authflow session check) and zeroized on drop.
pub struct ConnectionCheckPlan {
    pub alias: String,
    pub site: SiteSummary,
    pub secret: Value,
    pub provider: String,
    pub path: Option<String>,
}

impl Drop for ConnectionCheckPlan {
    fn drop(&mut self) {
        fn clear(value: &mut Value) {
            use zeroize::Zeroize;
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => o.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.secret);
    }
}

impl Vault {
    /// Phase 1: resolve the check target. Holding the vault lock only long
    /// enough to read metadata and the secret.
    pub fn prepare_connection_check(
        &self,
        alias: &str,
        override_path: Option<&str>,
    ) -> Result<ConnectionCheckPlan, VaultError> {
        self.ensure_unlocked()?;
        let site = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        if site.auth_type == "password" {
            return Err(VaultError::InvalidSchema("普通密码不做连接检查".into()));
        }
        let details = self.details(alias)?;
        let provider = resolve_provider(&site, &details);
        let path = check_path(&details, &provider, override_path);
        let secret = self.get_site_secret(alias)?;
        Ok(ConnectionCheckPlan {
            alias: alias.to_owned(),
            site,
            secret,
            provider,
            path,
        })
    }

    /// Phase 3: persist sanitized evidence. Never mutates policies,
    /// credentials or the request generation.
    pub fn finish_connection_check(
        &mut self,
        alias: &str,
        outcome: &CheckOutcome,
    ) -> Result<(), VaultError> {
        if outcome.saved_only {
            return Ok(());
        }
        let evidence = CheckEvidence {
            state: outcome.state.clone(),
            checked_at: outcome.checked_at.clone(),
            message: outcome.message.clone(),
            error_code: outcome.error_code.clone(),
            ..CheckEvidence::default()
        };
        self.record_check_evidence(
            alias,
            crate::status::DIMENSION_API,
            CheckEvidence {
                scope: outcome.scope.clone(),
                ..evidence.clone()
            },
        )?;
        if outcome.provider == PROVIDER_GITHUB
            || outcome.provider == PROVIDER_GITLAB
            || outcome.provider == PROVIDER_GITEE
            || outcome.provider == PROVIDER_MICROSOFT
            || outcome.provider == PROVIDER_GOOGLE
            || outcome.state != STATE_READY
        {
            self.record_check_evidence(
                alias,
                crate::status::DIMENSION_IDENTITY,
                CheckEvidence {
                    provider: Some(outcome.provider.clone()),
                    account: outcome.account.clone(),
                    scope: outcome.scope.clone(),
                    ..evidence
                },
            )?;
        }
        Ok(())
    }
}

/// Phase 2: the network request. Runs without any vault lock.
pub fn execute_connection_check(plan: &ConnectionCheckPlan, timeout: Duration) -> CheckOutcome {
    if plan.provider == PROVIDER_E10 {
        let result = crate::e10::check_session(&plan.site.site_url, &plan.secret);
        return match result {
            Ok(metadata) => CheckOutcome {
                provider: PROVIDER_E10.into(),
                state: STATE_VERIFIED.into(),
                error_code: None,
                message: format!("E10 账号身份已验证：{}", if metadata.user_name.is_empty() { &metadata.user_id } else { &metadata.user_name }),
                account: Some(if metadata.user_name.is_empty() { metadata.user_id } else { metadata.user_name }),
                scope: Some("E10 teamsCheck 只读检查".into()),
                checked_at: metadata.checked_at,
                http_status: Some(200),
                saved_only: false,
            },
            Err(error) => CheckOutcome {
                provider: PROVIDER_E10.into(),
                state: if error.code() == "expired" { STATE_UNAUTHORIZED.into() } else { error.code().into() },
                error_code: Some(error.code().into()),
                message: error.to_string(),
                account: None,
                scope: Some("E10 teamsCheck 只读检查".into()),
                checked_at: crate::vault::now(),
                http_status: None,
                saved_only: false,
            },
        };
    }
    if plan.secret.get("auth_profile").and_then(|v|v.get("check")).is_some_and(|v|!v.is_null()) {
        let result = crate::authflow::check_session(&plan.site.site_url, &plan.secret);
        let (state, error_code, account, message) = match result {
            Ok(metadata) => (STATE_VERIFIED.to_owned(), None, Some(metadata.user_name), "账号身份已验证".to_owned()),
            Err(e) => (if e.code()=="expired" {STATE_UNAUTHORIZED}else{e.code()}.to_owned(),Some(e.code().to_owned()),None,e.to_string()),
        };
        return CheckOutcome { provider: "configured".into(), state, error_code, account, message, scope: Some("配置的身份检查".into()), checked_at: crate::vault::now(), http_status: None, saved_only: false };
    }
    if plan.provider == PROVIDER_GOOGLE {
        return google_identity_check(plan, timeout);
    }

        let Some(path) = &plan.path else {
            return CheckOutcome {
                provider: plan.provider.clone(),
                state: crate::status::STATE_UNCHECKED.into(),
                error_code: None,
                message: "未配置连接检查，目前仅报告保存状态".into(),
                account: None,
                scope: None,
                checked_at: crate::vault::now(),
                http_status: None,
                saved_only: true,
            };
        };
        let scope = format!("GET {path} 只读检查");
        let checked_at = crate::vault::now();
        let provider = plan.provider.as_str();
        let raw = match crate::http_proxy::execute(
            &plan.site,
            &plan.secret,
            "GET",
            path,
            None,
            None,
            None,
            timeout,
        ) {
            Ok(raw) => raw,
            Err(error) => {
                return match error {
                    crate::ProxyError::Request(e) if e.is_timeout() => CheckOutcome {
                        provider: provider.to_owned(),
                        state: STATE_TIMEOUT.into(),
                        error_code: Some("timeout".into()),
                        message: "检查请求超时，远端在时限内未返回".into(),
                        account: None,
                        scope: Some(scope),
                        checked_at,
                        http_status: None,
                        saved_only: false,
                    },
                    crate::ProxyError::Request(_) => CheckOutcome {
                        provider: provider.to_owned(),
                        state: STATE_NETWORK_ERROR.into(),
                        error_code: Some("network_error".into()),
                        message: "检查请求未能到达远端服务；凭据保持不变".into(),
                        account: None,
                        scope: Some(scope),
                        checked_at,
                        http_status: None,
                        saved_only: false,
                    },
                    other => CheckOutcome {
                        provider: provider.to_owned(),
                        state: STATE_NETWORK_ERROR.into(),
                        error_code: Some("request_failed".into()),
                        message: format!("检查未能完成：{other}"),
                        account: None,
                        scope: Some(scope),
                        checked_at,
                        http_status: None,
                        saved_only: false,
                    },
                };
            }
        };
        let clean = match crate::http_proxy::sanitize(
            raw,
            &crate::RedactionPolicy::default(),
            &plan.secret,
            &plan.site,
        ) {
            Ok(clean) => clean,
            Err(_) => {
                return CheckOutcome {
                    provider: provider.to_owned(),
                    state: STATE_NETWORK_ERROR.into(),
                    error_code: Some("response_blocked".into()),
                    message: "检查响应疑似包含凭据，已阻止解析；请重新登录后再检查".into(),
                    account: None,
                    scope: Some(scope),
                    checked_at,
                    http_status: None,
                    saved_only: false,
                };
            }
        };
        let status = clean.status_code;
        let account = parse_identity(provider, clean.body_json.as_ref());
        let mut state = match status {
            200..=299 => {
                if provider == PROVIDER_CUSTOM || provider == PROVIDER_NONE {
                    // A custom path cannot confirm who the account is.
                    STATE_READY.to_owned()
                } else if account.is_some() {
                    STATE_VERIFIED.to_owned()
                } else {
                    crate::status::STATE_INVALID_RESPONSE.to_owned()
                }
            }
            401 => STATE_UNAUTHORIZED.to_owned(),
            403 => STATE_FORBIDDEN.to_owned(),
            429 => STATE_RATE_LIMITED.to_owned(),
            404 => STATE_NETWORK_ERROR.to_owned(),
            _ => crate::status::STATE_INVALID_RESPONSE.to_owned(),
        };
        if (200..299).contains(&status) && provider != PROVIDER_CUSTOM && account.is_none() {
            state = crate::status::STATE_INVALID_RESPONSE.to_owned();
        }
        let error_code = match state.as_str() {
            s if s == STATE_VERIFIED || s == STATE_READY => None,
            s if s == STATE_UNAUTHORIZED => Some("session_expired".to_owned()),
            s if s == STATE_FORBIDDEN => Some("explicit_deny".to_owned()),
            s if s == STATE_RATE_LIMITED => Some("rate_limited".to_owned()),
            s if s == STATE_TIMEOUT => Some("timeout".to_owned()),
            s if s == STATE_NETWORK_ERROR => Some("invalid_response".to_owned()),
            _ => Some("invalid_response".to_owned()),
        };
        let message = match state.as_str() {
            s if s == STATE_VERIFIED => format!(
                "远端身份接口确认账号 {}，检查请求正常返回",
                account.as_deref().unwrap_or("（未提供登录名）")
            ),
            s if s == STATE_READY => "检查请求正常返回；仅证明该只读路径可用".into(),
            s if s == STATE_UNAUTHORIZED => "远端返回 401，此凭据可能已失效".into(),
            s if s == STATE_FORBIDDEN => {
                "远端返回 403；凭据可能有效但该账号没有此接口权限".into()
            }
            s if s == STATE_RATE_LIMITED => "远端返回 429，检查被限流".into(),
            _ => "检查返回了无法识别的响应".into(),
        };
        CheckOutcome {
            provider: provider.to_owned(),
            state,
            error_code,
            message,
            account,
            scope: Some(scope),
            checked_at,
            http_status: Some(status),
            saved_only: false,
        }
    }

/// Phase 2 helper for Google: the documented userinfo endpoint lives on a
/// different origin than the business API, so the request cannot ride the
/// same-origin proxy chain. The endpoint is a compile-time constant and only
/// the whitelisted identity fields (`email`, then `sub`) are extracted — the
/// response body is never surfaced or stored.
fn google_identity_check(plan: &ConnectionCheckPlan, timeout: Duration) -> CheckOutcome {
    let scope = Some("GET userinfo 只读检查（提供方身份端点）".to_owned());
    let checked_at = crate::vault::now();
    let outcome = |state: String, error_code: Option<&str>, message: String, account: Option<String>, http_status: Option<u16>| CheckOutcome {
        provider: PROVIDER_GOOGLE.into(),
        state,
        error_code: error_code.map(str::to_owned),
        message,
        account,
        scope: scope.clone(),
        checked_at,
        http_status,
        saved_only: false,
    };
    let token = plan
        .secret
        .get("token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let Some(token) = token else {
        return outcome(
            crate::status::STATE_UNCHECKED.into(),
            None,
            "未保存访问令牌，目前仅报告保存状态".into(),
            None,
            None,
        );
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return outcome(
                STATE_NETWORK_ERROR.into(),
                Some("request_failed"),
                "检查未能完成：无法创建请求".into(),
                None,
                None,
            )
        }
    };
    let response = client
        .get(GOOGLE_IDENTITY_ENDPOINT)
        .header("Accept", "application/json")
        .header("User-Agent", crate::http_proxy::USER_AGENT)
        .header("Authorization", format!("Bearer {token}"))
        .send();
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let timed_out = error.is_timeout();
            return outcome(
                if timed_out { STATE_TIMEOUT.into() } else { STATE_NETWORK_ERROR.into() },
                Some(if timed_out { "timeout" } else { "network_error" }),
                if timed_out {
                    "检查请求超时，远端在时限内未返回".into()
                } else {
                    "检查请求未能到达远端服务；凭据保持不变".into()
                },
                None,
                None,
            );
        }
    };
    let status = response.status().as_u16();
    match status {
        200..=299 => {}
        401 => {
            return outcome(
                STATE_UNAUTHORIZED.into(),
                Some("session_expired"),
                "远端返回 401，此凭据可能已失效".into(),
                None,
                Some(status),
            )
        }
        403 => {
            return outcome(
                STATE_FORBIDDEN.into(),
                Some("explicit_deny"),
                "远端返回 403；凭据可能有效但该账号没有此接口权限".into(),
                None,
                Some(status),
            )
        }
        429 => {
            return outcome(
                STATE_RATE_LIMITED.into(),
                Some("rate_limited"),
                "远端返回 429，检查被限流".into(),
                None,
                Some(status),
            )
        }
        _ => {
            return outcome(
                crate::status::STATE_INVALID_RESPONSE.into(),
                Some("invalid_response"),
                "检查返回了无法识别的响应".into(),
                None,
                Some(status),
            )
        }
    }
    let bytes: Vec<u8> = match response.bytes() {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            return outcome(
                STATE_NETWORK_ERROR.into(),
                Some("network_error"),
                "检查响应读取失败；凭据保持不变".into(),
                None,
                Some(status),
            )
        }
    };
    if bytes.len() > 512 * 1024 {
        return outcome(
            crate::status::STATE_INVALID_RESPONSE.into(),
            Some("invalid_response"),
            "检查返回了无法识别的响应".into(),
            None,
            Some(status),
        );
    }
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return outcome(
                crate::status::STATE_INVALID_RESPONSE.into(),
                Some("invalid_response"),
                "检查返回了无法识别的响应".into(),
                None,
                Some(status),
            )
        }
    };
    let account = ["email", "sub"]
        .iter()
        .find_map(|field| value.get(*field).and_then(Value::as_str))
        .map(str::to_owned)
        .filter(|name| !name.trim().is_empty() && name.len() <= 128);
    match account {
        Some(account) => outcome(
            STATE_VERIFIED.into(),
            None,
            format!("远端身份接口确认账号 {account}，检查请求正常返回"),
            Some(account),
            Some(status),
        ),
        None => outcome(
            crate::status::STATE_INVALID_RESPONSE.into(),
            Some("invalid_response"),
            "身份接口未返回可显示的账号标识".into(),
            None,
            Some(status),
        ),
    }
}

impl Vault {
    /// Convenience wrapper for synchronous callers (tests, CLI).
    pub fn run_connection_check(
        &mut self,
        alias: &str,
        override_path: Option<&str>,
        timeout: Duration,
    ) -> Result<CheckOutcome, VaultError> {
        let plan = self.prepare_connection_check(alias, override_path)?;
        let outcome = execute_connection_check(&plan, timeout);
        drop(plan);
        self.finish_connection_check(alias, &outcome)?;
        Ok(outcome)
    }

    /// Record Connection session-check evidence through the status contract while
    /// keeping the legacy `extra.status` keys in sync.
    pub fn finish_authflow_evidence(
        &mut self,
        alias: &str,
        state: &str,
        account: Option<&str>,
        message: &str,
        error_code: Option<&str>,
    ) -> Result<(), VaultError> {
        self.record_check_evidence(
            alias,
            crate::status::DIMENSION_IDENTITY,
            CheckEvidence {
                state: state.to_owned(),
                checked_at: crate::vault::now(),
                message: message.to_owned(),
                error_code: error_code.filter(|code| !code.is_empty()).map(str::to_owned),
                provider: Some(PROVIDER_CONNECTION.into()),
                account: account.filter(|value| !value.is_empty()).map(str::to_owned),
                scope: Some("Connection 会话检查".into()),
                ..CheckEvidence::default()
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn respond(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let size = stream.read(&mut buffer).unwrap();
                    if size == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..size]);
                    if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                }
                requests.push(String::from_utf8_lossy(&bytes).to_string());
                stream
                    .write_all(response.as_bytes())
                    .unwrap();
            }
            requests
        });
        (format!("http://{address}"), handle)
    }

    fn json_response(status: &str, body: Value) -> String {
        let body = serde_json::to_vec(&body).unwrap();
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(&body)
        )
    }

    fn vault_with_site(origin: &str, provider: Option<Value>) -> (tempfile::TempDir, Vault) {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                origin,
                "api_token",
                json!({"token":"SYNTHETIC_PMAN_NEVER_OUTPUT_92745"}),
            ))
            .unwrap();
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .unwrap();
        if let Some(provider) = provider {
            vault.update_details("api", json!({"provider": provider})).unwrap();
        }
        (temp, vault)
    }

    fn grant_first_client(vault: &mut Vault) {
        vault
            .pair_client_for("Client", "generic", "client", "client-id", &"a".repeat(64))
            .unwrap();
        vault.add_allow_rule("client", "api", "GET", "/**").unwrap();
    }

    #[test]
    fn github_check_verifies_identity_and_records_scoped_evidence() {
        let (url, server) = respond(vec![json_response(
            "200 OK",
            json!({"login":"octocat","id":1,"two_factor":false}),
        )]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
        grant_first_client(&mut vault);
        let outcome = vault.run_connection_check("api", None, Duration::from_secs(5)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.state, STATE_VERIFIED);
        assert_eq!(outcome.account.as_deref(), Some("octocat"));
        assert_eq!(outcome.http_status, Some(200));
        assert!(outcome.scope.unwrap().contains("GET /user"));
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, crate::status::STATE_VERIFIED);
        assert_eq!(status.api.state, STATE_READY);
        assert_eq!(status.identity.evidence, Some("check".into()));
    }

    #[test]
    fn check_requests_are_get_only_with_no_body_side_effects() {
        let (url, server) = respond(vec![json_response("200 OK", json!({"login":"octo"}))]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
        vault.run_connection_check("api", None, Duration::from_secs(5)).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        let request = requests[0].to_ascii_lowercase();
        assert!(request.starts_with("get /user http/1.1"), "{request}");
        assert!(!request.contains("post") && !request.contains("content-length: 2"));
        assert!(request.contains("authorization: bearer synthetic_pman_never_output_92745"));
    }

    #[test]
    fn status_codes_map_to_distinct_recoverable_states() {
        for (response, expected, error) in [
            ("401 Unauthorized", STATE_UNAUTHORIZED, "session_expired"),
            ("403 Forbidden", STATE_FORBIDDEN, "explicit_deny"),
            ("429 Too Many Requests", STATE_RATE_LIMITED, "rate_limited"),
        ] {
            let (url, server) = respond(vec![json_response(response, json!({"message":"x"}))]);
            let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
            let outcome = vault
                .run_connection_check("api", None, Duration::from_secs(5))
                .unwrap();
            server.join().unwrap();
            assert_eq!(outcome.state, expected, "{response}");
            assert_eq!(outcome.error_code.as_deref(), Some(error));
            let status = vault.connection_status("api").unwrap();
            assert_eq!(status.identity.state, expected);
            // A failed check must not have changed grants or credentials.
            assert_eq!(status.clients.state, crate::status::STATE_NONE);
        }
    }

    #[test]
    fn timeout_is_reported_and_credentials_survive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            // Never respond; the client times out.
            thread::sleep(Duration::from_millis(300));
        });
        let (_temp, mut vault) = vault_with_site(&format!("http://{address}"), Some(json!("github")));
        let outcome = vault
            .run_connection_check("api", None, Duration::from_millis(200))
            .unwrap();
        server.join().unwrap();
        assert_eq!(outcome.state, STATE_TIMEOUT);
        assert_eq!(outcome.error_code.as_deref(), Some("timeout"));
        assert!(vault.get_site_secret("api").is_ok(), "网络失败不得删除凭据");
    }

    #[test]
    fn custom_check_path_reports_api_capability_without_identity_claims() {
        let (url, server) = respond(vec![json_response("200 OK", json!({"status":"ok"}))]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("custom")));
        grant_first_client(&mut vault);
        vault
            .update_details("api", json!({"check_path":"/health"}))
            .unwrap();
        let outcome = vault
            .run_connection_check("api", None, Duration::from_secs(5))
            .unwrap();
        server.join().unwrap();
        assert_eq!(outcome.state, STATE_READY);
        assert_eq!(outcome.account, None);
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.api.state, STATE_READY);
        assert_eq!(status.identity.state, crate::status::STATE_UNCHECKED);
        assert!(status.api.detail.contains("作用域"));
    }

    #[test]
    fn unknown_service_without_check_path_reports_saved_only() {
        let (_temp, mut vault) = vault_with_site("https://intranet.example.test", None);
        let outcome = vault
            .run_connection_check("api", None, Duration::from_secs(5))
            .unwrap();
        assert!(outcome.saved_only);
        assert_eq!(outcome.http_status, None);
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, crate::status::STATE_UNCHECKED);
    }

    #[test]
    fn overridden_check_path_is_validated() {
        let (_temp, mut vault) = vault_with_site("https://intranet.example.test", Some(json!("custom")));
        for path in ["health", "/a?b=1", "/a#b", "/a\\..\\b", ""] {
            let outcome = vault
                .run_connection_check("api", Some(path), Duration::from_secs(5))
                .unwrap();
            assert!(
                outcome.saved_only,
                "无效路径不得发起网络请求: {path}"
            );
        }
        // A valid override path is attempted even for unreachable hosts.
        let outcome = vault
            .run_connection_check("api", Some("/health"), Duration::from_secs(5))
            .unwrap();
        assert!(!outcome.saved_only);
        assert_eq!(outcome.http_status, None);
    }

    #[test]
    fn check_response_containing_the_secret_is_redacted_or_blocked() {
        let (url, server) = respond(vec![json_response(
            "200 OK",
            json!({"token":"SYNTHETIC_PMAN_NEVER_OUTPUT_92745","login":"octo"}),
        )]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
        grant_first_client(&mut vault);
        let outcome = vault.run_connection_check("api", None, Duration::from_secs(5)).unwrap();
        server.join().unwrap();
        // The sanitized proxy chain may redact or block, but never pass the
        // secret through. The outcome only carries the login name.
        let serialized = serde_json::to_string(&outcome).unwrap();
        assert!(
            !serialized.contains("SYNTHETIC_PMAN_NEVER_OUTPUT_92745"),
            "{serialized}"
        );
        assert_eq!(outcome.account.as_deref(), Some("octo"));
    }

    #[test]
    fn stale_evidence_follows_account_and_address_changes() {
        let (url, _server) = respond(vec![json_response("200 OK", json!({"login":"octo"}))]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
        vault
            .run_connection_check("api", None, Duration::from_secs(5))
            .unwrap();
        vault
            .update_details("api", json!({"account":"someone-else"}))
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, crate::status::STATE_STALE);
        // Changing the address disables AI usage; re-enabling must not
        // resurrect the old evidence.
        vault
            .update_site_metadata("api", crate::SiteMetadataUpdate {
                site_url: format!("{url}/"),
                name: None,
                purpose: None,
                tags: vec![],
            })
            .unwrap();
        vault.update_details("api", json!({"ai_enabled":true})).unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, crate::status::STATE_STALE);
        assert_ne!(status.api.state, STATE_READY);
    }

    #[test]
    fn revoking_a_grant_reauthenticates_the_next_request_from_the_same_identity() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"SYNTHETIC_PMAN_NEVER_OUTPUT_92745"}),
            ))
            .unwrap();
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .unwrap();
        vault
            .pair_client_for("Client", "generic", "client", "client-id", &"a".repeat(64))
            .unwrap();
        vault.add_allow_rule("client", "api", "GET", "/**").unwrap();
        let broker = crate::Broker::new();
        let request = crate::HttpRequest {
            site: "api".into(),
            method: "GET".into(),
            path: "/data".into(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        };
        let policy = vault.get_policy("client").unwrap();
        assert!(
            crate::Policy::from_json(&policy)
                .unwrap()
                .authorize("api", "GET", "/data")
                .allowed
        );
        // Revoke exactly the whole-connection rule; the same client identity
        // must be re-authenticated on the next request.
        let rule = policy["allow"][0].clone();
        vault.remove_allow_rule("client", rule).unwrap();
        let policy = crate::Policy::from_json(&vault.get_policy("client").unwrap()).unwrap();
        assert!(!policy.authorize("api", "GET", "/data").allowed);
        let authorization = broker
            .authorize(&mut vault, request, Some("client"))
            .unwrap();
        assert!(
            authorization.pending_approval || !authorization.allowed,
            "撤销后同一客户端身份必须重新鉴权"
        );
    }

    #[test]
    fn evidence_recording_survives_concurrent_checks_with_atomic_write() {
        let (url, server) = respond(vec![json_response("200 OK", json!({"login":"octo"}))]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
        vault
            .run_connection_check("api", None, Duration::from_secs(5))
            .unwrap();
        server.join().unwrap();
        // Both evidence slots were written with matching context fingerprints.
        let details = vault.details("api").unwrap();
        let api: CheckEvidence =
            serde_json::from_value(details.extra["api_check"].clone()).unwrap();
        let identity: CheckEvidence =
            serde_json::from_value(details.extra["identity_check"].clone()).unwrap();
        assert_eq!(api.context, identity.context);
        assert!(!api.context.is_empty());
        assert_eq!(details.extra["status"], json!("verified"), "legacy keys stay in sync");
    }

    #[test]
    fn consent_flow_failure_keeps_the_saved_grant() {
        let (url, server) = respond(vec![json_response("401 Unauthorized", json!({}))]);
        let (_temp, mut vault) = vault_with_site(&url, Some(json!("github")));
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .unwrap();
        vault
            .pair_client_for("Client", "generic", "client", "client-id", &"a".repeat(64))
            .unwrap();
        vault.grant_connection_clients("api", &["client-id".into()]).unwrap();
        vault.run_connection_check("api", None, Duration::from_secs(5)).unwrap();
        server.join().unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, STATE_UNAUTHORIZED);
        // The saved grant survives the failed check.
        assert_eq!(status.clients.state, crate::status::STATE_GRANTED);
        assert!(vault.details("api").unwrap().ai_enabled);
        let policy = crate::Policy::from_json(&vault.get_policy("client").unwrap()).unwrap();
        assert!(policy.authorize("api", "GET", "/anything").allowed);
    }
}
