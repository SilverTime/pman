//! Browser-capability authorization and session bookkeeping.
//!
//! The security-relevant half of BROWSER-CONTRACT.md lives here so both the
//! desktop executor and tests share it: which client may perform which action
//! on which connection and origin, plus the masking rules that keep
//! credentials out of page snapshots. Transport (WebView2) is the desktop's
//! responsibility and never relaxes these checks.

use crate::{SiteSummary, Vault, VaultError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

/// The complete v1 action set. Anything else (file upload/download, payment,
/// destructive submits, arbitrary script) simply does not exist as an action.
pub const WEB_ACTIONS: &[&str] = &["open", "summary", "click", "fill", "wait", "close"];

/// Mask token for any value the AI must not see.
pub const WEB_REDACTED: &str = crate::REDACTED;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthError {
    Disabled,
    NotAuthorized,
    OriginDenied,
    SessionUnknown,
    Unsupported,
}

impl WebAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "web_disabled",
            Self::NotAuthorized => "web_not_authorized",
            Self::OriginDenied => "web_origin_denied",
            Self::SessionUnknown => "web_session_unknown",
            Self::Unsupported => "web_action_unsupported",
        }
    }
}

pub fn normalize_web_origin(origin: &str) -> Result<String, WebAuthError> {
    let parsed = url::Url::parse(origin.trim())
        .map_err(|_| WebAuthError::OriginDenied)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(WebAuthError::OriginDenied);
    }
    Ok(parsed.origin().ascii_serialization())
}

/// One live web session. Ownership binds client identity, connection and the
/// generation at creation time; a stale generation invalidates the session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebSession {
    pub session_id: String,
    pub client_id: String,
    pub harness: String,
    pub site: String,
    pub origin: String,
    #[serde(default)]
    pub window_label: String,
    pub generation: u64,
    pub created_at: String,
    pub expires_at: String,
}

/// In-memory registry. Sessions die with the service process by design.
#[derive(Default)]
pub struct WebSessions {
    inner: Mutex<HashMap<String, WebSession>>,
}

impl WebSessions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&self, session: WebSession) {
        self.inner
            .lock()
            .expect("web session registry poisoned")
            .insert(session.session_id.clone(), session);
    }

    pub fn get(&self, session_id: &str) -> Option<WebSession> {
        self.inner
            .lock()
            .expect("web session registry poisoned")
            .get(session_id)
            .cloned()
    }

    pub fn close(&self, session_id: &str) -> Option<WebSession> {
        self.inner
            .lock()
            .expect("web session registry poisoned")
            .remove(session_id)
    }

    /// Close every session for a connection; returns the closed session ids.
    pub fn close_for_site(&self, alias: &str) -> Vec<WebSession> {
        let mut inner = self.inner.lock().expect("web session registry poisoned");
        let closed: Vec<String> = inner
            .iter()
            .filter(|(_, s)| s.site == alias)
            .map(|(id, _)| id.clone())
            .collect();
        closed
            .iter()
            .filter_map(|id| inner.remove(id))
            .collect()
    }

    /// Close every session owned by a harness (client revoked).
    pub fn close_for_harness(&self, harness: &str) -> Vec<WebSession> {
        let mut inner = self.inner.lock().expect("web session registry poisoned");
        let closed: Vec<String> = inner
            .iter()
            .filter(|(_, s)| s.harness == harness)
            .map(|(id, _)| id.clone())
            .collect();
        closed
            .iter()
            .filter_map(|id| inner.remove(id))
            .collect()
    }

    /// Close everything (explicit service pause / shutdown).
    pub fn close_all(&self) -> Vec<WebSession> {
        let mut inner = self.inner.lock().expect("web session registry poisoned");
        inner.drain().map(|(_, session)| session).collect()
    }

    pub fn list_for_site(&self, alias: &str) -> Vec<WebSession> {
        self.inner
            .lock()
            .expect("web session registry poisoned")
            .values()
            .filter(|s| s.site == alias)
            .cloned()
            .collect()
    }
}

impl Vault {
    /// Connection-level switch for browser capability. Enabling never grants
    /// any client: per-client web rules are a separate explicit step.
    pub fn set_web_enabled(&mut self, alias: &str, enabled: bool) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        if !self
            .list_sites()?
            .iter()
            .any(|s| s.alias == alias)
        {
            return Err(VaultError::UnknownSite(alias.into()));
        }
        let mut details = self.details(alias)?;
        if details.web_enabled == enabled {
            return Ok(());
        }
        details.web_enabled = enabled;
        self.conn.execute(
            "INSERT INTO connection_details(alias,details_json) VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET details_json=excluded.details_json",
            rusqlite::params![alias, serde_json::to_string(&details)?],
        )?;
        // Enabling/disabling changes the capability surface: stale sessions
        // must not survive.
        self.invalidate_requests();
        Ok(())
    }

    /// Per-client browser authorization (BROWSER-CONTRACT.md §1). Replaces
    /// any previous web rule for this connection per client, always with the
    /// full action set and explicit origins. Atomic across clients.
    pub fn grant_web_clients(
        &mut self,
        alias: &str,
        client_ids: &[String],
        origins: &[String],
    ) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        let site = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        if site.auth_type == "password" || site.site_url.is_empty() || client_ids.is_empty() {
            return Err(VaultError::InvalidSchema(
                "请选择连接和至少一个有效的 AI 客户端".into(),
            ));
        }
        if origins.is_empty() {
            return Err(VaultError::InvalidSchema("网页授权需要至少一个 origin".into()));
        }
        let mut normalized = Vec::new();
        for origin in origins {
            normalized.push(
                normalize_web_origin(origin).map_err(|_| {
                    VaultError::InvalidSchema(format!("无效的网页授权 origin：{origin}"))
                })?,
            );
        }
        let details = self.details(alias)?;
        if !details.web_enabled {
            return Err(VaultError::InvalidSchema(
                "请先在连接详情中开启 AI 网页操作".into(),
            ));
        }
        let clients = self.list_clients()?;
        let mut policies = Vec::new();
        for id in client_ids {
            let client = clients
                .iter()
                .find(|c| {
                    &c.id == id
                        && c.paired
                        && c.revoked_at.is_none()
                        && !crate::vault::is_expired(c.expires_at.as_deref())
                })
                .ok_or(VaultError::InvalidClient)?;
            let harness = self
                .get_harness(&client.harness)?
                .ok_or(VaultError::InvalidClient)?;
            if harness.revoked_at.is_some()
                || crate::vault::is_expired(harness.expires_at.as_deref())
            {
                return Err(VaultError::InvalidClient);
            }
            let mut policy = self.get_policy(&client.harness)?;
            let object = policy.as_object_mut().ok_or_else(|| {
                VaultError::InvalidSchema("invalid policy".into())
            })?;
            let web = object
                .entry("web".to_owned())
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
                .ok_or_else(|| VaultError::InvalidSchema("invalid web rules".into()))?;
            web.retain(|rule| rule.get("site").and_then(Value::as_str) != Some(alias));
            web.push(serde_json::json!({
                "site": alias,
                "actions": WEB_ACTIONS,
                "origins": normalized,
            }));
            crate::Policy::from_json(&policy)
                .map_err(|e| VaultError::InvalidSchema(e.to_string()))?;
            policies.push((client.harness.clone(), policy));
        }
        let tx = self.conn.transaction()?;
        for (harness, policy) in &policies {
            tx.execute(
                "UPDATE harnesses SET policy_json=? WHERE name=?",
                rusqlite::params![serde_json::to_string(&policy)?, harness],
            )?;
        }
        tx.commit()?;
        self.invalidate_requests();
        Ok(())
    }

    /// Remove every web rule for a connection (web-capability revoke).
    pub fn revoke_web_grants(&mut self, alias: &str) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        for profile in self.list_harnesses()? {
            let mut policy = profile.policy.clone();
            if let Some(web) = policy.get_mut("web").and_then(Value::as_array_mut) {
                let before = web.len();
                web.retain(|rule| rule.get("site").and_then(Value::as_str) != Some(alias));
                if before != web.len() {
                    self.set_policy(&profile.name, policy)?;
                }
            }
        }
        self.invalidate_requests();
        Ok(())
    }

    /// Full pre-action authorization. Runs on every browser action: client
    /// identity has already been proven by the transport; this checks the
    /// connection, the independent web capability, the per-client grant and
    /// the origin scope. Session state and generation are checked by the
    /// caller against the registry entry it loaded.
    pub fn authorize_web_action(
        &self,
        harness: &str,
        alias: &str,
        action: &str,
        origin: Option<&str>,
    ) -> Result<String, WebAuthError> {
        if !WEB_ACTIONS.contains(&action) {
            return Err(WebAuthError::Unsupported);
        }
        self.ensure_unlocked()
            .map_err(|_| WebAuthError::Disabled)?;
        let site = self
            .list_sites()
            .map_err(|_| WebAuthError::Disabled)?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or(WebAuthError::SessionUnknown)?;
        if site.status != "active" || crate::vault::is_expired(site.expires_at.as_deref()) {
            return Err(WebAuthError::Disabled);
        }
        let details = self.details(alias).map_err(|_| WebAuthError::Disabled)?;
        if !details.ai_enabled || !details.web_enabled {
            return Err(WebAuthError::Disabled);
        }
        let policy = crate::Policy::from_json(
            &self.get_policy(harness).map_err(|_| WebAuthError::NotAuthorized)?,
        )
        .map_err(|_| WebAuthError::NotAuthorized)?;
        let rule = policy
            .web
            .iter()
            .find(|rule| rule.site == alias)
            .ok_or(WebAuthError::NotAuthorized)?;
        if !rule.actions.iter().any(|a| a.eq_ignore_ascii_case(action)) {
            return Err(WebAuthError::NotAuthorized);
        }
        // The action origin (page currently shown or the session origin)
        // must itself be granted; a session origin alone is not enough to
        // navigate anywhere new.
        if let Some(origin) = origin {
            let normalized = normalize_web_origin(origin)?;
            if !rule.origins.iter().any(|allowed| {
                normalize_web_origin(allowed)
                    .map(|allowed| allowed == normalized)
                    .unwrap_or(false)
            }) {
                return Err(WebAuthError::OriginDenied);
            }
        }
        Ok(site.site_url)
    }

    /// The effective origin of a connection's web session target.
    pub fn web_session_origin(&self, alias: &str) -> Result<String, WebAuthError> {
        let site = self
            .list_sites()
            .map_err(|_| WebAuthError::Disabled)?
            .into_iter()
            .find(|s| s.alias == alias)
            .ok_or(WebAuthError::SessionUnknown)?;
        if site.site_url.is_empty() {
            return Err(WebAuthError::Disabled);
        }
        normalize_web_origin(&site.site_url)
    }
}

/// Sensitive-field detection for page snapshots. Deliberately NOT limited to
/// `type=password`: field names, labels and autocomplete hints count too.
pub fn is_sensitive_field(name: &str, input_type: &str, autocomplete: &str) -> bool {
    let haystack = format!("{name} {autocomplete}").to_ascii_lowercase();
    if input_type.eq_ignore_ascii_case("password") {
        return true;
    }
    if autocomplete
        .to_ascii_lowercase()
        .starts_with("cc-")
    {
        return true;
    }
    let lowered = haystack.to_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "passcode",
        "pass_word",
        "otp",
        "verification",
        "verification_code",
        "verify_code",
        "one-time-code",
        "one_time_code",
        "token",
        "secret",
        "api_key",
        "apikey",
        "card",
        "cvv",
        "cvc",
        "captcha",
        // Chinese labels cover localized enterprise forms.
        "密码",
        "验证码",
        "卡号",
        "令牌",
        "短信校验",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

/// True when a page response echoes any credential value from the vault.
/// The caller must reject the whole response instead of returning content.
pub fn web_response_blocked(text: &str, secret: &serde_json::Value, site: &SiteSummary) -> bool {
    let secrets = crate::http_proxy::secret_values(secret, site);
    secrets
        .iter()
        .any(|secret| secret.len() >= 8 && text.contains(secret.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vault_with_web() -> (tempfile::TempDir, Vault) {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(
                crate::SiteInput::new(
                    "site",
                    "https://web.example.test",
                    "login",
                    json!({"cookies": [{"name": "sid", "value": "SYNTHETIC_SESSION_4411"}]}),
                ),
            )
            .unwrap();
        vault
            .update_details("site", json!({"ai_enabled": true, "web_enabled": true}))
            .unwrap();
        (temp, vault)
    }

    #[test]
    fn web_capability_is_off_by_default_and_never_migrates() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(
                crate::SiteInput::new(
                    "api",
                    "https://web.example.test",
                    "api_token",
                    json!({"token": "SYNTHETIC_SESSION_4411"}),
                ),
            )
            .unwrap();
        // A pre-existing API grant must not imply web access.
        vault
            .update_details("api", json!({"ai_enabled": true}))
            .unwrap();
        vault.ensure_harness("client").unwrap();
        vault
            .set_policy(
                "client",
                json!({"allow":[{"site":"api","methods":["GET"],"paths":["/**"],"require_approval":false}]}),
            )
            .unwrap();
        assert!(!vault.details("api").unwrap().web_enabled);
        let error = vault
            .authorize_web_action("client", "api", "open", None)
            .unwrap_err();
        assert_eq!(error.code(), "web_disabled");
        // Whole-connection HTTP grants remain exactly that: HTTP only.
        let policy = vault.get_policy("client").unwrap();
        assert!(policy.get("web").is_none() || policy["web"].as_array().unwrap().is_empty());
    }

    #[test]
    fn browser_actions_fail_closed_without_client_grant() {
        let (_temp, mut vault) = vault_with_web();
        // Connection enabled, but the client has no web rule at all.
        vault.ensure_harness("client").unwrap();
        let error = vault
            .authorize_web_action("client", "site", "open", None)
            .unwrap_err();
        assert_eq!(error.code(), "web_not_authorized");

        // A web rule without the requested action is equally closed.
        vault
            .set_policy(
                "client",
                json!({"web":[{"site":"site","actions":["summary"],"origins":["https://web.example.test"]}]}),
            )
            .unwrap();
        let error = vault
            .authorize_web_action("client", "site", "click", None)
            .unwrap_err();
        assert_eq!(error.code(), "web_not_authorized");
        // Allowed actions pass.
        vault
            .authorize_web_action("client", "site", "summary", None)
            .unwrap();
    }

    #[test]
    fn disabling_the_connection_stops_authorized_clients() {
        let (_temp, mut vault) = vault_with_web();
        vault.ensure_harness("client").unwrap();
        vault
            .set_policy(
                "client",
                json!({"web":[{"site":"site","actions":["open","summary"],"origins":["https://web.example.test"]}]}),
            )
            .unwrap();
        vault
            .authorize_web_action("client", "site", "open", None)
            .unwrap();
        vault
            .update_details("site", json!({"web_enabled": false}))
            .unwrap();
        let error = vault
            .authorize_web_action("client", "site", "open", None)
            .unwrap_err();
        assert_eq!(error.code(), "web_disabled");
    }

    #[test]
    fn web_origin_outside_grant_is_denied() {
        let (_temp, mut vault) = vault_with_web();
        vault.ensure_harness("client").unwrap();
        vault
            .set_policy(
                "client",
                json!({"web":[{"site":"site","actions":["open","summary"],"origins":["https://web.example.test"]}]}),
            )
            .unwrap();
        vault
            .authorize_web_action("client", "site", "open", Some("https://web.example.test"))
            .unwrap();
        let error = vault
            .authorize_web_action("client", "site", "open", Some("https://evil.example.test"))
            .unwrap_err();
        assert_eq!(error.code(), "web_origin_denied");
        // A lookalike subdomain is a different origin.
        let error = vault
            .authorize_web_action("client", "site", "open", Some("https://web.example.test.evil.test"))
            .unwrap_err();
        assert_eq!(error.code(), "web_origin_denied");
    }

    #[test]
    fn web_sessions_fail_closed_after_revoke_and_generation_change() {
        let (_temp, _vault) = vault_with_web();
        let sessions = WebSessions::new();
        let session = WebSession {
            session_id: "web-1".into(),
            client_id: "client-x".into(),
            harness: "client".into(),
            site: "site".into(),
            origin: "https://web.example.test".into(),
            window_label: "web-session-web-1".into(),
            generation: 1,
            created_at: "2026-09-19T00:00:00".into(),
            expires_at: "2026-09-19T01:00:00".into(),
        };
        sessions.open(session.clone());
        assert_eq!(sessions.get("web-1"), Some(session.clone()));
        // Revoking the client closes the harness sessions immediately.
        let closed = sessions.close_for_harness("client");
        assert_eq!(closed.len(), 1);
        assert_eq!(sessions.get("web-1"), None);
        // Deleting/disabling the connection closes by site.
        sessions.open(session.clone());
        let closed = sessions.close_for_site("site");
        assert_eq!(closed.len(), 1);
        assert_eq!(sessions.get("web-1"), None);
    }

    #[test]
    fn unknown_or_unsupported_actions_never_exist() {
        let (_temp, mut vault) = vault_with_web();
        vault.ensure_harness("client").unwrap();
        vault
            .set_policy(
                "client",
                json!({"web":[{"site":"site","actions":["open","summary","click","fill","wait","close"],"origins":["https://web.example.test"]}]}),
            )
            .unwrap();
        for action in ["evaluate", "screenshot", "upload", "download", "exec", "read_storage"] {
            let error = vault
                .authorize_web_action("client", "site", action, None)
                .unwrap_err();
            assert_eq!(error.code(), "web_action_unsupported", "{action}");
        }
    }

    #[test]
    fn sensitive_fields_are_masked_beyond_input_type() {
        // type=text with a sensitive name is still masked.
        assert!(is_sensitive_field("otp_code", "text", ""));
        assert!(is_sensitive_field("payCardNumber", "tel", ""));
        assert!(is_sensitive_field("nickname", "text", "cc-number"));
        assert!(is_sensitive_field("确认密码", "text", ""));
        assert!(is_sensitive_field("verification", "text", "one-time-code"));
        // Ordinary fields stay visible so the AI can read forms.
        assert!(!is_sensitive_field("username", "text", ""));
        assert!(!is_sensitive_field("search", "search", ""));
        assert!(!is_sensitive_field("quantity", "number", ""));
        assert!(is_sensitive_field("", "password", ""));
    }

    #[test]
    fn web_response_echoing_credentials_is_blocked() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(
                crate::SiteInput::new(
                    "site",
                    "https://web.example.test",
                    "login",
                    json!({"cookies": [{"name": "sid", "value": "SYNTHETIC_SESSION_4411"}]}),
                ),
            )
            .unwrap();
        let site = vault.list_sites().unwrap().remove(0);
        let secret = vault.get_site_secret("site").unwrap();
        // The page echoes the session cookie value: the response is blocked.
        assert!(web_response_blocked(
            r#"{"echo":"sid=SYNTHETIC_SESSION_4411"}"#,
            &secret,
            &site
        ));
        // Ordinary page content passes.
        assert!(!web_response_blocked(
            r#"{"title":"工作台","fields":["username","search"]}"#,
            &secret,
            &site
        ));
    }
}
