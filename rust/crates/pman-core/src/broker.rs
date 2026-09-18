//! Broker authorization boundary.
//!
//! This module deliberately separates authorization from HTTP transport. A
//! request must pass this boundary before a future reqwest adapter can inject
//! a site secret. Approval payloads are redacted before they touch SQLite.

use crate::{
    http_proxy::{self, ProxyError},
    AuditEntryInput, HttpRequest, Policy, PolicyError, ProtocolError, RateLimiter, ResultEnvelope,
    Vault, VaultError,
};
use pman_protocol::{
    ERROR_HARNESS_INVALID, ERROR_INVALID_REQUEST, ERROR_PENDING_APPROVAL, ERROR_POLICY_DENIED,
    ERROR_RATE_LIMITED, ERROR_REQUEST_FAILED, ERROR_RESPONSE_BLOCKED, ERROR_SITE_INACTIVE,
    ERROR_UNKNOWN_SITE, ERROR_VAULT_LOCKED,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use thiserror::Error;

pub const APPROVAL_STICKY_SECONDS: i64 = 600;
pub const REDACTED: &str = "***REDACTED***";

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("策略拒绝：{0}")]
    PolicyDenied(String),
    #[error("超过配额：{0}")]
    RateLimited(String),
    #[error("未知 harness：{0}")]
    UnknownHarness(String),
    #[error("harness {0} 已被吊销")]
    RevokedHarness(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Authorization {
    pub allowed: bool,
    pub approval_required: bool,
    pub approved: bool,
    pub pending_approval: bool,
    pub access_required: bool,
    pub req_id: Option<String>,
    pub request_fingerprint: Option<String>,
}

/// Stable wire result returned by the Rust broker and Tauri commands.
///
/// Optional fields are omitted on failures so callers can distinguish a
/// transport error from an HTTP response (including 4xx/5xx responses).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrokerResult {
    #[serde(flatten)]
    pub envelope: ResultEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_unknown: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_json: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_original_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_denied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_blocked: Option<bool>,
}

impl BrokerResult {
    fn success(clean: crate::CleanResponse) -> Self {
        Self {
            envelope: ResultEnvelope::ok(),
            outcome_unknown: None,
            request_id: None,
            error: None,
            status_code: Some(clean.status_code),
            headers: Some(clean.headers),
            body_json: clean.body_json,
            body_text: clean.body_text,
            redactions: Some(clean.redactions),
            truncated: Some(clean.truncated),
            truncated_original_bytes: Some(clean.truncated_original_bytes),
            pending_approval: None,
            access_required: None,
            req_id: None,
            approval_status: None,
            policy_denied: None,
            rate_limited: None,
            response_blocked: None,
        }
    }

    pub fn failure(code: &str, error: impl Into<String>) -> Self {
        Self {
            envelope: ResultEnvelope::error(code),
            outcome_unknown: None,
            request_id: None,
            error: Some(error.into()),
            status_code: None,
            headers: None,
            body_json: None,
            body_text: None,
            redactions: None,
            truncated: None,
            truncated_original_bytes: None,
            pending_approval: None,
            access_required: None,
            req_id: None,
            approval_status: None,
            policy_denied: None,
            rate_limited: None,
            response_blocked: None,
        }
    }

    fn pending(req_id: String, access_required: bool) -> Self {
        let mut result = Self::failure(
            ERROR_PENDING_APPROVAL,
            format!("该操作需要人工审批，请运行：pm approve {req_id}"),
        );
        result.pending_approval = Some(true);
        result.access_required = Some(access_required);
        result.req_id = Some(req_id);
        result.approval_status = Some("pending".to_owned());
        result
    }
}

impl Authorization {
    fn allowed(approval_required: bool, approved: bool, fingerprint: Option<String>) -> Self {
        Self {
            allowed: true,
            approval_required,
            approved,
            pending_approval: false,
            access_required: false,
            req_id: None,
            request_fingerprint: fingerprint,
        }
    }

    fn pending(req_id: String, fingerprint: String, access_required: bool) -> Self {
        Self {
            allowed: false,
            approval_required: true,
            approved: false,
            pending_approval: true,
            access_required,
            req_id: Some(req_id),
            request_fingerprint: Some(fingerprint),
        }
    }
}

#[derive(Default)]
pub struct Broker {
    rate_limiter: RateLimiter,
}

/// Secret-bearing transport work. Intentionally neither Debug nor Serialize.
pub struct PreparedCall {
    lifecycle_id: String,
    audit_request: HttpRequest,
    request: HttpRequest,
    site: crate::SiteSummary,
    policy: Policy,
    secret: Value,
    harness: Option<String>,
    approved: bool,
    generation: u64,
    generation_signal: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// Contains only sanitized data and correlation metadata.
pub struct CompletedCall {
    lifecycle_id: String,
    audit_request: HttpRequest,
    transport_attempted: bool,
    response_received: bool,
    request: HttpRequest,
    harness: Option<String>,
    approved: bool,
    generation: u64,
    generation_signal: std::sync::Arc<std::sync::atomic::AtomicU64>,
    result: BrokerResult,
}

impl PreparedCall {
    pub fn execute(self) -> CompletedCall {
        if self
            .generation_signal
            .load(std::sync::atomic::Ordering::Acquire)
            != self.generation
        {
            return CompletedCall {
                lifecycle_id: self.lifecycle_id.clone(),
                audit_request: self.audit_request.clone(),
                transport_attempted: false,
                response_received: false,
                request: self.request.clone(),
                harness: self.harness.clone(),
                approved: self.approved,
                generation: self.generation,
                generation_signal: self.generation_signal.clone(),
                result: BrokerResult::failure(
                    ERROR_POLICY_DENIED,
                    "Service or authorization changed before dispatch",
                ),
            };
        }
        let mut response_received = false;
        let mut transport_attempted = true;
        let mut result = match http_proxy::execute(
            &self.site,
            &self.secret,
            &self.request.method,
            &self.request.path,
            self.request.query.as_ref(),
            self.request.json_body.as_ref(),
            self.request.form.as_ref(),
            std::time::Duration::from_secs(60),
        ) {
            Ok(raw) => {
                response_received = true;
                match http_proxy::sanitize(raw, &self.policy.redact, &self.secret, &self.site) {
                    Ok(clean) => BrokerResult::success(clean),
                    Err(error) => Broker::new().proxy_error_result(error),
                }
            }
            Err(error) => {
                if matches!(
                    error,
                    ProxyError::InvalidRequest
                        | ProxyError::MissingSecret
                        | ProxyError::UnsupportedAuthType
                        | ProxyError::GitlabCsrf
                ) {
                    transport_attempted = false;
                }
                if matches!(&error,ProxyError::Request(error) if error.is_builder()) {
                    transport_attempted = false;
                }
                Broker::new().proxy_error_result(error)
            }
        };
        result.request_id = Some(self.lifecycle_id.clone());
        if transport_attempted && !response_received {
            result.outcome_unknown = Some(true);
            result.error =
                Some("Remote outcome unknown after dispatch failure; no automatic retry".into());
        }
        CompletedCall {
            lifecycle_id: self.lifecycle_id.clone(),
            audit_request: self.audit_request.clone(),
            transport_attempted,
            response_received,
            request: self.request.clone(),
            harness: self.harness.clone(),
            approved: self.approved,
            generation: self.generation,
            generation_signal: self.generation_signal.clone(),
            result,
        }
    }
}

impl Drop for PreparedCall {
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

impl Broker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compatibility convenience. Desktop/IPC use prepare/execute/finish so HTTP never owns the vault mutex.
    pub fn call(
        &self,
        vault: &mut Vault,
        request: HttpRequest,
        harness: Option<&str>,
    ) -> BrokerResult {
        let prepared = match self.prepare(vault, request, harness) {
            Ok(p) => p,
            Err(e) => return e,
        };
        self.finish(vault, prepared.execute())
    }

    pub fn prepare(
        &self,
        vault: &mut Vault,
        request: HttpRequest,
        harness: Option<&str>,
    ) -> Result<PreparedCall, BrokerResult> {
        let request = request
            .validate()
            .map_err(|e| BrokerResult::failure(ERROR_INVALID_REQUEST, e.to_string()))?;
        let authorization = self
            .authorize(vault, request.clone(), harness)
            .map_err(|e| self.error_result(e))?;
        if authorization.pending_approval {
            return Err(BrokerResult::pending(
                authorization.req_id.unwrap_or_default(),
                authorization.access_required,
            ));
        }
        let site = vault
            .list_sites()
            .map_err(|e| self.error_result(e.into()))?
            .into_iter()
            .find(|s| s.alias == request.site)
            .ok_or_else(|| BrokerResult::failure(ERROR_UNKNOWN_SITE, "Unknown connection"))?;
        if site.auth_type == "password" {
            return Err(BrokerResult::failure(
                ERROR_POLICY_DENIED,
                "This password item has no callable connection",
            ));
        }
        let policy = self
            .policy_for(vault, harness)
            .map_err(|e| self.error_result(e))?;
        let secret = vault
            .get_site_secret(&request.site)
            .map_err(|e| self.error_result(e.into()))?;
        let secrets = http_proxy::secret_values(&secret, &site);
        let clean_route = |text: &str| {
            secrets
                .iter()
                .filter(|s| !s.is_empty())
                .fold(text.to_owned(), |value, secret| {
                    value.replace(secret, REDACTED)
                })
        };
        let audit_request = HttpRequest {
            site: clean_route(&request.site),
            method: request.method.clone(),
            path: clean_route(&request.path),
            capability: request.capability.clone(),
            query: None,
            json_body: None,
            form: None,
        };
        let lifecycle_id = vault
            .begin_request_lifecycle(
                harness.unwrap_or("human"),
                &audit_request.site,
                &audit_request.method,
                &audit_request.path,
            )
            .map_err(|e| self.error_result(e.into()))?;
        Ok(PreparedCall {
            lifecycle_id,
            audit_request,
            request,
            site,
            policy,
            secret,
            harness: harness.map(str::to_owned),
            approved: authorization.approved,
            generation: vault.generation(),
            generation_signal: vault.generation_signal(),
        })
    }

    /// A policy change or explicit pause discards in-flight output, including already-sent writes.
    pub fn finish(&self, vault: &mut Vault, completed: CompletedCall) -> BrokerResult {
        let same_session =
            std::sync::Arc::ptr_eq(&vault.generation_signal(), &completed.generation_signal);
        let failure = |code: &str, message: &str| {
            let mut result = BrokerResult::failure(code, message);
            result.request_id = Some(completed.lifecycle_id.clone());
            result.outcome_unknown = completed.transport_attempted.then_some(true);
            result
        };
        if same_session {
            let state = if !completed.transport_attempted {
                "not_dispatched"
            } else if completed.response_received {
                "response_received"
            } else {
                "outcome_unknown"
            };
            if vault
                .finish_request_lifecycle(&completed.lifecycle_id, state)
                .is_err()
            {
                return failure(ERROR_REQUEST_FAILED,"Unable to persist dispatch outcome; remote outcome unknown, no automatic retry");
            }
        }
        if !vault.unlocked() || vault.generation() != completed.generation || !same_session {
            self.audit_failure(vault,completed.harness.as_deref(),&completed.audit_request,None,"Authorization changed during dispatch; remote outcome may be unknown; no automatic retry");
            return failure(
                if vault.unlocked() {
                    ERROR_POLICY_DENIED
                } else {
                    ERROR_VAULT_LOCKED
                },
                "Authorization changed during request; response withheld, no automatic retry",
            );
        }
        if let Some(ref harness) = completed.harness {
            let valid = vault.get_harness(harness).ok().flatten().is_some_and(|h| {
                h.revoked_at.is_none() && !crate::vault::is_expired(h.expires_at.as_deref())
            });
            if !valid {
                return failure(ERROR_HARNESS_INVALID,"Client authorization expired or revoked; response withheld, no automatic retry");
            }
            if !completed.approved
                && !self
                    .policy_for(vault, Some(harness))
                    .is_ok_and(|p| p.authorize_request(&completed.request).allowed)
            {
                return failure(
                    ERROR_POLICY_DENIED,
                    "Grant expired during request; response withheld, no automatic retry",
                );
            }
        }
        let result = completed.result;
        if result.envelope.ok {
            let _ = vault.touch_site(&completed.request.site);
        }
        let _ = self.audit_response(
            vault,
            completed.harness.as_deref(),
            &completed.audit_request,
            result.status_code,
            result.truncated_original_bytes.unwrap_or(0),
            result.redactions.unwrap_or(0),
            result.truncated.unwrap_or(false),
            completed.approved,
            Some(&completed.lifecycle_id),
            if result.envelope.ok {
                None
            } else {
                Some(
                    if result.outcome_unknown == Some(true) {
                        "Remote outcome unknown after dispatch failure; no automatic retry"
                    } else {
                        "Request failed or response withheld; no automatic retry"
                    }
                    .into(),
                )
            },
        );
        result
    }

    /// Run policy, rate-limit and approval checks without touching the network.
    pub fn authorize(
        &self,
        vault: &mut Vault,
        request: HttpRequest,
        harness: Option<&str>,
    ) -> Result<Authorization, BrokerError> {
        let request = request.validate()?;
        vault.ensure_unlocked()?;
        let site = vault
            .list_sites()?
            .into_iter()
            .find(|site| site.alias == request.site)
            .ok_or_else(|| VaultError::UnknownSite(request.site.clone()))?;
        if site.status != "active" || crate::vault::is_expired(site.expires_at.as_deref()) {
            return Err(VaultError::InactiveSite(request.site).into());
        }
        let Some(harness) = harness else {
            return Ok(Authorization::allowed(false, false, None));
        };
        let profile = vault
            .get_harness(harness)?
            .ok_or_else(|| BrokerError::UnknownHarness(harness.to_owned()))?;
        if profile.revoked_at.is_some() {
            return Err(BrokerError::RevokedHarness(harness.to_owned()));
        }
        let policy = Policy::from_json(&profile.policy)?;
        if crate::vault::is_expired(profile.expires_at.as_deref()) {
            return Err(BrokerError::RevokedHarness(harness.to_owned()));
        }
        if !vault.details(&request.site)?.ai_enabled {
            return Err(BrokerError::PolicyDenied(
                "AI access is disabled for this connection".into(),
            ));
        }
        if policy.explicitly_denied_request(&request) {
            return Err(BrokerError::PolicyDenied("Explicit deny rule".into()));
        }
        let decision = policy.authorize_request(&request);
        if let Err(reason) = self
            .rate_limiter
            .check(harness, policy.rate_limit.req_per_min)
        {
            self.audit(
                vault,
                harness,
                &request,
                None,
                false,
                Some(format!("限流:{reason}")),
            )?;
            return Err(BrokerError::RateLimited(reason));
        }

        let fingerprint = vault.approval_fingerprint(
            &request.site,
            &request.method,
            &request.path,
            request.capability.as_deref(),
            request.query.as_ref(),
            request.json_body.as_ref(),
            request.form.as_ref(),
        )?;
        let boundary_approval = !decision.allowed;
        let method_approval = policy.approval_required_for_request(&request);
        if !boundary_approval && !method_approval {
            return Ok(Authorization::allowed(false, false, Some(fingerprint)));
        }
        if vault.consume_recent_approval(
            harness,
            &request.site,
            &request.method,
            &request.path,
            &fingerprint,
            APPROVAL_STICKY_SECONDS,
        )? {
            return Ok(Authorization::allowed(true, true, Some(fingerprint)));
        }

        let secret = vault.get_site_secret(&request.site).ok();
        let payload = redact_request_payload(&request, &policy, secret.as_ref());
        let req_id = vault.create_approval(
            harness,
            &request.site,
            &request.method,
            &request.path,
            &payload,
            Some(&fingerprint),
        )?;
        self.audit(
            vault,
            harness,
            &request,
            Some(&req_id),
            false,
            Some(if boundary_approval {
                "等待范围授权".to_owned()
            } else {
                "等待人工审批".to_owned()
            }),
        )?;
        Ok(Authorization::pending(
            req_id,
            fingerprint,
            boundary_approval,
        ))
    }

    fn policy_for(&self, vault: &Vault, harness: Option<&str>) -> Result<Policy, BrokerError> {
        let Some(harness) = harness else {
            return Ok(Policy::default());
        };
        let value = vault.get_policy(harness)?;
        Ok(Policy::from_json(&value)?)
    }

    fn error_result(&self, error: BrokerError) -> BrokerResult {
        match error {
            BrokerError::Vault(error) => match error {
                VaultError::Locked => BrokerResult::failure(ERROR_VAULT_LOCKED, "保险库未解锁"),
                VaultError::UnknownSite(site) => {
                    BrokerResult::failure(ERROR_UNKNOWN_SITE, format!("未知站点：{site}"))
                }
                VaultError::InactiveSite(site) => {
                    BrokerResult::failure(ERROR_SITE_INACTIVE, format!("站点 {site} 已停用"))
                }
                VaultError::UnknownHarness(harness) => {
                    BrokerResult::failure(ERROR_HARNESS_INVALID, format!("未知 harness：{harness}"))
                }
                _ => BrokerResult::failure(ERROR_REQUEST_FAILED, "请求失败"),
            },
            BrokerError::Policy(error) => {
                BrokerResult::failure(ERROR_REQUEST_FAILED, error.to_string())
            }
            BrokerError::Protocol(error) => {
                BrokerResult::failure(ERROR_INVALID_REQUEST, error.to_string())
            }
            BrokerError::PolicyDenied(reason) => {
                let mut result = BrokerResult::failure(ERROR_POLICY_DENIED, reason);
                result.policy_denied = Some(true);
                result
            }
            BrokerError::RateLimited(reason) => {
                let mut result = BrokerResult::failure(ERROR_RATE_LIMITED, reason);
                result.rate_limited = Some(true);
                result
            }
            BrokerError::UnknownHarness(harness) => {
                BrokerResult::failure(ERROR_HARNESS_INVALID, format!("未知 harness：{harness}"))
            }
            BrokerError::RevokedHarness(harness) => {
                BrokerResult::failure(ERROR_HARNESS_INVALID, format!("harness {harness} 已被吊销"))
            }
        }
    }

    fn proxy_error_result(&self, error: ProxyError) -> BrokerResult {
        match error {
            ProxyError::GitlabCsrf => BrokerResult::failure(
                ERROR_REQUEST_FAILED,
                "GitLab CSRF 认证准备失败，未发送写入请求；请检查或刷新连接登录",
            ),
            ProxyError::ResponseBlocked => {
                let mut result = BrokerResult::failure(
                    ERROR_RESPONSE_BLOCKED,
                    "响应疑似包含站点凭据，已阻止返回",
                );
                result.response_blocked = Some(true);
                result
            }
            _ => BrokerResult::failure(ERROR_REQUEST_FAILED, "请求失败"),
        }
    }

    fn audit_failure(
        &self,
        vault: &mut Vault,
        harness: Option<&str>,
        request: &HttpRequest,
        response: Option<(u16, usize, usize, bool)>,
        note: &str,
    ) {
        let (status_code, resp_bytes, redactions, truncated) = response
            .map(|(status, bytes, redactions, truncated)| {
                (Some(status), bytes, redactions, truncated)
            })
            .unwrap_or((None, 0, 0, false));
        let _ = self.audit_response(
            vault,
            harness,
            request,
            status_code,
            resp_bytes,
            redactions,
            truncated,
            false,
            None,
            Some(note.to_owned()),
        );
    }

    fn audit_response(
        &self,
        vault: &mut Vault,
        harness: Option<&str>,
        request: &HttpRequest,
        status_code: Option<u16>,
        resp_bytes: usize,
        redactions: usize,
        truncated: bool,
        approved: bool,
        req_id: Option<&str>,
        note: Option<String>,
    ) -> Result<(), VaultError> {
        vault.add_audit(&AuditEntryInput {
            harness: harness.unwrap_or("human").to_owned(),
            site: Some(request.site.clone()),
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            status_code: status_code.map(|status| status as i64),
            resp_bytes: resp_bytes as i64,
            redactions: redactions as i64,
            truncated,
            approved,
            req_id: req_id.map(str::to_owned),
            note,
            ..AuditEntryInput::default()
        })
    }

    fn audit(
        &self,
        vault: &mut Vault,
        harness: &str,
        request: &HttpRequest,
        req_id: Option<&str>,
        approved: bool,
        note: Option<String>,
    ) -> Result<(), VaultError> {
        vault.add_audit(&AuditEntryInput {
            harness: harness.to_owned(),
            site: Some(request.site.clone()),
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            req_id: req_id.map(str::to_owned),
            approved,
            note,
            ..AuditEntryInput::default()
        })
    }
}

fn redact_request_payload(request: &HttpRequest, policy: &Policy, secret: Option<&Value>) -> Value {
    let secret_values = secret.map(collect_secret_values).unwrap_or_default();
    let mut payload = Map::new();
    if let Some(capability) = &request.capability {
        payload.insert("capability".to_owned(), Value::String(capability.clone()));
    }
    payload.insert(
        "query".to_owned(),
        redact_value(request.query.as_ref(), None, policy, &secret_values),
    );
    payload.insert(
        "json_body".to_owned(),
        redact_value(request.json_body.as_ref(), None, policy, &secret_values),
    );
    payload.insert(
        "form".to_owned(),
        redact_value(request.form.as_ref(), None, policy, &secret_values),
    );
    Value::Object(payload)
}

fn redact_value(
    value: Option<&Value>,
    key: Option<&str>,
    policy: &Policy,
    secrets: &[String],
) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    if key.is_some_and(|key| is_sensitive_key(key, policy)) {
        return Value::String(REDACTED.to_owned());
    }
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        redact_value(Some(value), Some(key), policy, secrets),
                    )
                })
                .collect(),
        ),
        Value::Array(array) => Value::Array(
            array
                .iter()
                .map(|value| redact_value(Some(value), None, policy, secrets))
                .collect(),
        ),
        Value::String(text)
            if secrets
                .iter()
                .any(|secret| !secret.is_empty() && text.contains(secret)) =>
        {
            Value::String(REDACTED.to_owned())
        }
        _ => value.clone(),
    }
}

fn is_sensitive_key(key: &str, policy: &Policy) -> bool {
    let lower = key.to_ascii_lowercase();
    policy.redact.json_keys.iter().any(|pattern| {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return false;
        }
        let pattern = pattern.trim_start_matches("(?i)");
        let has_regex_syntax = pattern.contains('*')
            || pattern.contains('.')
            || pattern.contains('[')
            || pattern.contains('(')
            || pattern.contains('?')
            || pattern.contains('|')
            || pattern.contains('^')
            || pattern.contains('$');
        if has_regex_syntax {
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map(|regex| regex.is_match(key))
                .unwrap_or(false)
        } else {
            lower.contains(&pattern.to_ascii_lowercase())
        }
    }) || [
        "token",
        "password",
        "passwd",
        "secret",
        "cookie",
        "authorization",
        "api_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn collect_secret_values(value: &Value) -> Vec<String> {
    let mut values = Vec::new();
    collect_strings(value, &mut values);
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    values.dedup();
    values
}

fn collect_strings(value: &Value, values: &mut Vec<String>) {
    match value {
        Value::String(text) if !text.is_empty() => values.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect_strings(item, values)),
        Value::Object(items) => items
            .values()
            .for_each(|item| collect_strings(item, values)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SiteInput;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    #[test]
    fn approval_payload_is_redacted_and_bound_to_request() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault
            .add_site(SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"secret-value"}),
            ))
            .expect("site");
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .expect("AI access");
        vault.ensure_harness("codex").expect("harness");
        vault.set_policy("codex", json!({"allow":[{"site":"api","methods":["POST"],"paths":["/write"]}],"approval":{"required_for":["POST"]}})).expect("policy");
        let broker = Broker::new();
        let request = HttpRequest {
            site: "api".to_owned(),
            method: "POST".to_owned(),
            path: "/write".to_owned(),
            capability: None,
            query: None,
            json_body: Some(json!({"title":"ok","token":"request-secret"})),
            form: None,
        };
        let pending = broker
            .authorize(&mut vault, request.clone(), Some("codex"))
            .expect("authorization");
        assert!(pending.pending_approval);
        let row = vault
            .get_approval(pending.req_id.as_deref().unwrap())
            .expect("approval")
            .expect("row");
        assert_eq!(row.payload["json_body"]["token"], REDACTED);
        assert!(!serde_json::to_string(&row)
            .unwrap()
            .contains("request-secret"));
        vault
            .decide_approval(pending.req_id.as_deref().unwrap(), true, "human")
            .expect("decide");
        let allowed = broker
            .authorize(&mut vault, request, Some("codex"))
            .expect("authorization");
        assert!(allowed.allowed && allowed.approved);
        let changed = HttpRequest {
            json_body: Some(json!({"title":"different"})),
            ..HttpRequest {
                site: "api".to_owned(),
                method: "POST".to_owned(),
                path: "/write".to_owned(),
                capability: None,
                query: None,
                json_body: None,
                form: None,
            }
        };
        let second = broker
            .authorize(&mut vault, changed, Some("codex"))
            .expect("authorization");
        assert!(second.pending_approval);
    }

    #[test]
    fn persistent_approval_creates_revocable_scope_without_reusing_one_shot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault
            .add_site(SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"secret-value"}),
            ))
            .expect("site");
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .expect("AI access");
        vault.ensure_harness("codex").expect("harness");
        vault
            .set_policy(
                "codex",
                json!({
                    "allow":[{"site":"api","methods":["POST"],"paths":["/write"],"require_approval":true}],
                    "approval":{"required_for":["POST"]}
                }),
            )
            .expect("policy");
        let broker = Broker::new();
        let first = HttpRequest {
            site: "api".to_owned(),
            method: "POST".to_owned(),
            path: "/write".to_owned(),
            capability: None,
            query: None,
            json_body: Some(json!({"value": 1})),
            form: None,
        };
        let pending = broker
            .authorize(&mut vault, first, Some("codex"))
            .expect("pending authorization");
        assert!(pending.pending_approval);

        let decided = vault
            .approve_persistently(pending.req_id.as_deref().unwrap(), "human")
            .expect("persistent decision")
            .expect("approval row");
        assert_eq!(decided.status, "approved");
        assert!(decided.consumed_at.is_some());
        let policy = Policy::from_json(&vault.get_policy("codex").expect("saved policy"))
            .expect("valid policy");
        assert!(!policy.approval_required_for("api", "POST", "/write"));

        let changed_body = HttpRequest {
            site: "api".to_owned(),
            method: "POST".to_owned(),
            path: "/write".to_owned(),
            capability: None,
            query: Some(json!({"page": 2})),
            json_body: Some(json!({"value": 2})),
            form: None,
        };
        let allowed = broker
            .authorize(&mut vault, changed_body, Some("codex"))
            .expect("persistent authorization");
        assert!(allowed.allowed);
        assert!(!allowed.approved);
        assert!(!allowed.approval_required);

        let other_path = HttpRequest {
            site: "api".to_owned(),
            method: "POST".to_owned(),
            path: "/other".to_owned(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        };
        let outside = broker
            .authorize(&mut vault, other_path, Some("codex"))
            .expect("outside authorization");
        assert!(outside.pending_approval);
    }

    #[test]
    fn out_of_scope_request_enters_one_time_access_approval() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault
            .add_site(SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"secret-value"}),
            ))
            .expect("site");
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .expect("AI access");
        vault.ensure_harness("codex").expect("harness");
        let broker = Broker::new();
        let request = HttpRequest {
            site: "api".to_owned(),
            method: "GET".to_owned(),
            path: "/outside".to_owned(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        };

        let pending = broker
            .authorize(&mut vault, request, Some("codex"))
            .expect("authorization");
        assert!(pending.pending_approval);
        assert!(pending.access_required);
        assert!(vault
            .list_approvals("pending")
            .expect("approvals")
            .iter()
            .any(|approval| approval.harness == "codex" && approval.path == "/outside"));
    }

    #[test]
    fn call_injects_secret_and_returns_sanitized_protocol_result() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let (sender, receiver) = mpsc::channel();
        let body = json!({"data":[1,2,3],"access_token":"server-value","echo":"secret-token"});
        let body_bytes = serde_json::to_vec(&body).expect("body");
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sender.send(String::from_utf8_lossy(&request).to_string());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body_bytes.len(),
                String::from_utf8_lossy(&body_bytes),
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let mut vault = Vault::open(temp.path()).expect("open");
        vault.create("pw").expect("create");
        vault
            .add_site(SiteInput::new(
                "api",
                format!("http://{address}"),
                "api_token",
                json!({"token":"secret-token"}),
            ))
            .expect("site");
        let result = Broker::new().call(
            &mut vault,
            HttpRequest {
                site: "api".to_owned(),
                method: "GET".to_owned(),
                path: "/data".to_owned(),
                capability: None,
                query: None,
                json_body: None,
                form: None,
            },
            None,
        );
        thread.join().expect("server");
        let request = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("captured request");
        assert!(result.envelope.ok);
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.body_json.as_ref().unwrap()["access_token"], REDACTED);
        assert_eq!(result.body_json.as_ref().unwrap()["echo"], REDACTED);
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("secret-token"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-token"));
    }

    #[test]
    fn pause_after_prepare_prevents_dispatch_and_same_generation_new_vault_cannot_release_response()
    {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path().join("original")).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(SiteInput::new(
                "api",
                "http://127.0.0.1:9",
                "api_token",
                json!({"token":"synthetic-secret"}),
            ))
            .unwrap();
        let broker = Broker::new();
        let request = HttpRequest {
            site: "api".into(),
            method: "POST".into(),
            path: "/write".into(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        };
        let prepared = broker.prepare(&mut vault, request, None).unwrap();
        vault.lock();
        let completed = prepared.execute();
        assert_eq!(completed.result.envelope.error_code, ERROR_POLICY_DENIED);
        let mut replacement = Vault::open(temp.path().join("replacement")).unwrap();
        replacement.create("synthetic-password").unwrap();
        replacement.invalidate_requests(); // Same numeric generation, but a different service session.
        let result = broker.finish(&mut replacement, completed);
        assert!(!result.envelope.ok);
    }

    #[test]
    fn one_approval_is_consumed_once_under_parallel_calls() {
        use std::sync::{Arc, Mutex};
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"synthetic-secret"}),
            ))
            .unwrap();
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .unwrap();
        vault.ensure_harness("codex").unwrap();
        let broker = Arc::new(Broker::new());
        let request = HttpRequest {
            site: "api".into(),
            method: "POST".into(),
            path: "/write".into(),
            capability: None,
            query: None,
            json_body: Some(json!({"value":1})),
            form: None,
        };
        let pending = broker
            .authorize(&mut vault, request.clone(), Some("codex"))
            .unwrap();
        vault
            .decide_approval(pending.req_id.as_deref().unwrap(), true, "human")
            .unwrap();
        let vault = Arc::new(Mutex::new(vault));
        let tasks = (0..8)
            .map(|_| {
                let vault = vault.clone();
                let broker = broker.clone();
                let request = request.clone();
                std::thread::spawn(move || {
                    broker
                        .authorize(&mut vault.lock().unwrap(), request, Some("codex"))
                        .unwrap()
                        .approved
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .filter(|approved| *approved)
                .count(),
            1
        );
    }
}
