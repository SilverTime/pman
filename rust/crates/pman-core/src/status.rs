//! Connection status contract: five independently observable dimensions.
//!
//! Credential storage, remote identity verification, API capability, browser
//! capability and client authorization are different evidence. None of them
//! may be collapsed into a single "connected" flag, and unknown states must
//! surface as "尚未检查" instead of being assumed healthy. Persisted evidence
//! is sanitized metadata only: no secret value ever enters this module.

use crate::{Vault, VaultError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DIMENSION_CREDENTIAL: &str = "credential";
pub const DIMENSION_IDENTITY: &str = "identity";
pub const DIMENSION_API: &str = "api";
pub const DIMENSION_WEB: &str = "web";
pub const DIMENSION_CLIENTS: &str = "clients";

/// Stable state codes. The UI renders the label and never invents its own.
pub const STATE_UNCHECKED: &str = "unchecked";
pub const STATE_SAVED: &str = "saved";
pub const STATE_EXPIRED: &str = "expired";
pub const STATE_INACTIVE: &str = "inactive";
pub const STATE_VERIFIED: &str = "verified";
pub const STATE_UNAUTHORIZED: &str = "unauthorized";
pub const STATE_FORBIDDEN: &str = "forbidden";
pub const STATE_RATE_LIMITED: &str = "rate_limited";
pub const STATE_TIMEOUT: &str = "timeout";
pub const STATE_NETWORK_ERROR: &str = "network_error";
pub const STATE_INVALID_RESPONSE: &str = "invalid_response";
pub const STATE_STALE: &str = "stale";
pub const STATE_NOT_AVAILABLE: &str = "not_available";
pub const STATE_PAUSED: &str = "paused";
pub const STATE_NOT_GRANTED: &str = "not_granted";
pub const STATE_CLIENT_INVALID: &str = "client_invalid";
pub const STATE_READY: &str = "ready";
pub const STATE_NONE: &str = "none";
pub const STATE_GRANTED: &str = "granted";
pub const STATE_INVALID: &str = "invalid";
pub const STATE_RESTRICTED: &str = "restricted";

/// One observable dimension with its last evidence. Everything here is safe
/// to display; error text comes from fixed recovery strings, not responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DimensionStatus {
    pub state: String,
    pub label: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
    /// Which evidence produced the state: `check`, `usage`, `grants` or `policy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl DimensionStatus {
    fn new(state: &str, label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            state: state.to_owned(),
            label: label.into(),
            detail: detail.into(),
            checked_at: None,
            error_code: None,
            recovery: None,
            evidence: None,
        }
    }
    fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence = Some(evidence.to_owned());
        self
    }
    fn checked(mut self, at: impl Into<String>) -> Self {
        self.checked_at = Some(at.into());
        self
    }
    fn errored(mut self, code: &str, recovery: &str) -> Self {
        self.error_code = Some(code.to_owned());
        self.recovery = Some(recovery.to_owned());
        self
    }
    fn recovery(mut self, recovery: &str) -> Self {
        self.recovery = Some(recovery.to_owned());
        self
    }
}

/// The five dimensions for one connection. They are independent: a verified
/// identity does not prove API capability, and neither proves web capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionStatus {
    pub alias: String,
    pub credential: DimensionStatus,
    pub identity: DimensionStatus,
    pub api: DimensionStatus,
    pub web: DimensionStatus,
    pub clients: DimensionStatus,
}

/// Persisted check result. Kept inside `connection_details.extra` with
/// serde defaults so existing vaults open unchanged and gain no capability.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct CheckEvidence {
    pub state: String,
    pub checked_at: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub error_code: Option<String>,
    /// Fingerprint of the account context the check ran against. A changed
    /// fingerprint marks the evidence stale; it never auto-refreshes grants.
    #[serde(default)]
    pub context: String,
    /// Provider or check path, e.g. `github`, `gitlab`, `authflow`, `custom:/path`.
    #[serde(default)]
    pub provider: Option<String>,
    /// Redacted display identity from the remote, e.g. a login name.
    #[serde(default)]
    pub account: Option<String>,
    /// What the check actually proves, shown to the user verbatim.
    #[serde(default)]
    pub scope: Option<String>,
}

impl Vault {
    /// Fingerprint of the account context. Check evidence bound to a previous
    /// context is stale and must not be displayed as current.
    pub(crate) fn status_context_fingerprint(
        details: &crate::ConnectionDetails,
        site_url: &str,
    ) -> String {
        let canonical = format!(
            "{}|{}|{}|{}",
            site_url.trim_end_matches('/'),
            details.account.trim(),
            details.tenant.trim(),
            details.environment.trim()
        );
        hex::encode(Sha256::digest(canonical.as_bytes()))[..16].to_owned()
    }

    fn current_fingerprint(&self, alias: &str) -> Result<String, VaultError> {
        let details = self.details(alias)?;
        let site_url = self
            .list_sites()?
            .into_iter()
            .find(|s| s.alias == alias)
            .map(|s| s.site_url)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))?;
        Ok(Self::status_context_fingerprint(&details, &site_url))
    }

    /// Record sanitized check evidence for one dimension. This never touches
    /// policies, generation counters or account bindings: a check is evidence,
    /// not an authorization change. Legacy `extra.status`/`extra.checked_at`
    /// keys stay in sync for backward-compatible readers.
    pub fn record_check_evidence(
        &mut self,
        alias: &str,
        dimension: &str,
        mut evidence: CheckEvidence,
    ) -> Result<(), VaultError> {
        if !matches!(dimension, DIMENSION_IDENTITY | DIMENSION_API) {
            return Err(VaultError::InvalidSchema(
                "unsupported check dimension".into(),
            ));
        }
        if evidence.state.is_empty() || evidence.checked_at.is_empty() {
            return Err(VaultError::InvalidSchema(
                "check evidence is incomplete".into(),
            ));
        }
        self.ensure_unlocked()?;
        evidence.context = self.current_fingerprint(alias)?;
        let mut details = self.details(alias)?;
        if !details.extra.is_object() {
            details.extra = serde_json::json!({});
        }
        let object = details.extra.as_object_mut().expect("extra is object");
        object.insert(
            format!("{dimension}_check"),
            serde_json::to_value(&evidence)?,
        );
        if dimension == DIMENSION_IDENTITY {
            // Legacy consumers (bookshelf badges) read these keys.
            object.insert("status".into(), Value::String(evidence.state.clone()));
            object.insert(
                "checked_at".into(),
                Value::String(evidence.checked_at.clone()),
            );
        }
        self.conn.execute(
            "INSERT INTO connection_details(alias,details_json) VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET details_json=excluded.details_json",
            rusqlite::params![alias, serde_json::to_string(&details)?],
        )?;
        Ok(())
    }

    fn evidence_for(details: &crate::ConnectionDetails, dimension: &str) -> Option<CheckEvidence> {
        details
            .extra
            .get(&format!("{dimension}_check"))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    }

    /// Legacy evidence written by earlier authflow checks before the contract existed.
    fn legacy_identity_evidence(details: &crate::ConnectionDetails) -> Option<CheckEvidence> {
        let state = details.extra.get("status")?.as_str()?;
        if state.is_empty() {
            return None;
        }
        Some(CheckEvidence {
            state: state.to_owned(),
            checked_at: details
                .extra
                .get("checked_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            message: String::new(),
            error_code: None,
            context: String::new(),
            provider: None,
            account: details
                .extra
                .get("user_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            scope: None,
        })
    }
}

impl Vault {
    /// Compute the five status dimensions for every connection in one pass.
    pub fn connection_statuses(&self) -> Result<Vec<ConnectionStatus>, VaultError> {
        let sites = self.list_sites()?;
        let harnesses = self.list_harnesses()?;
        let clients = self.list_clients()?;
        let audit = self.query_audit(None, 500)?;
        let mut result = Vec::with_capacity(sites.len());
        for site in &sites {
            let details = self.details(&site.alias)?;
            let fingerprint = Self::status_context_fingerprint(&details, &site.site_url);
            result.push(compute_connection_status(
                site,
                &details,
                fingerprint,
                &harnesses,
                &clients,
                &audit,
            ));
        }
        Ok(result)
    }

    /// Compute the five status dimensions for one connection.
    pub fn connection_status(&self, alias: &str) -> Result<ConnectionStatus, VaultError> {
        self.connection_statuses()?
            .into_iter()
            .find(|status| status.alias == alias)
            .ok_or_else(|| VaultError::UnknownSite(alias.into()))
    }
}

fn compute_connection_status(
    site: &crate::SiteSummary,
    details: &crate::ConnectionDetails,
    fingerprint: String,
    harnesses: &[crate::HarnessSummary],
    clients: &[crate::ClientSummary],
    audit: &[crate::AuditEntry],
) -> ConnectionStatus {
    let alias = &site.alias;
    let personal = site.auth_type == "password";
    let expired = crate::vault::is_expired(site.expires_at.as_deref());
    let oauth_pending = details
        .extra
        .get("oauth_pending")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Dimension 1: credential storage. Always known from the vault itself.
    let credential = if personal {
        DimensionStatus::new(
            STATE_SAVED,
            "已保存",
            "普通密码仅本人保管，不作为 AI 连接使用。",
        )
        .with_evidence("policy")
    } else if oauth_pending {
        DimensionStatus::new(
            STATE_UNCHECKED,
            "等待 OAuth 登录",
            "连接资料已保存，但还没有取得可用令牌。完成登录后才能检查或授权 AI。",
        )
        .with_evidence("policy")
        .recovery("继续 OAuth 登录")
    } else if site.status != "active" {
        DimensionStatus::new(STATE_INACTIVE, "已停用", "连接已停用，恢复后才能继续使用。")
            .with_evidence("policy")
            .recovery("在连接管理中恢复连接")
    } else if expired {
        DimensionStatus::new(
            STATE_EXPIRED,
            if matches!(site.auth_type.as_str(), "login" | "authflow" | "e10") {
                "需重新登录"
            } else {
                "凭据已过期"
            },
            "凭据有效期已过，需要重新验证。",
        )
        .with_evidence("policy")
        .errored("session_expired", "重新登录或更新凭据")
    } else {
        DimensionStatus::new(STATE_SAVED, "已保存", "凭据已加密保存在本机保险库。")
            .with_evidence("policy")
    };

    // Dimension 2: remote identity verification. Unknown until checked.
    let identity = if personal {
        DimensionStatus::new(STATE_NOT_AVAILABLE, "不适用", "个人密码不做身份验证。")
            .with_evidence("policy")
    } else {
        let raw = Vault::evidence_for(details, DIMENSION_IDENTITY)
            .or_else(|| Vault::legacy_identity_evidence(details));
        match raw {
            None => DimensionStatus::new(
                STATE_UNCHECKED,
                "尚未检查",
                "还没有用远端只读接口验证过此账号身份。",
            )
            .with_evidence("policy"),
            Some(evidence) if evidence.context.is_empty() || evidence.context == fingerprint => {
                identity_from_evidence(&evidence)
            }
            Some(evidence) => DimensionStatus::new(
                STATE_STALE,
                "检查结果已过期",
                "检查之后账号、地址或环境已变化，旧结果不再可信。",
            )
            .with_evidence("check")
            .checked(evidence.checked_at)
            .errored("account_context_changed", "重新检查或重新登录"),
        }
    };

    // Dimension 3: API capability through the local proxy.
    let (active_clients, invalid_clients, restricted) = grant_summary(alias, harnesses, clients);
    let api = if personal {
        DimensionStatus::new(STATE_NOT_AVAILABLE, "不开放", "普通密码不向 AI 开放。")
            .with_evidence("policy")
    } else {
        let has_rules = active_clients + invalid_clients > 0;
        if !details.ai_enabled && !has_rules {
            DimensionStatus::new(
                STATE_NOT_GRANTED,
                "未授权 AI",
                "此连接还没有开放 AI 使用，也没有任何客户端授权。",
            )
            .with_evidence("grants")
            .recovery("在连接详情中选择授权 AI")
        } else if !details.ai_enabled {
            DimensionStatus::new(
                STATE_PAUSED,
                "已暂停",
                "此连接已暂停 AI 使用，已有授权暂时不生效。",
            )
            .with_evidence("policy")
            .recovery("在连接详情中恢复 AI 使用")
        } else if active_clients == 0 && invalid_clients == 0 {
            DimensionStatus::new(
                STATE_NOT_GRANTED,
                "未授权 AI",
                "还没有任何 AI 客户端被允许使用此连接。",
            )
            .with_evidence("grants")
            .recovery("在连接详情中选择授权 AI")
        } else if active_clients == 0 {
            DimensionStatus::new(
                STATE_CLIENT_INVALID,
                "客户端已失效",
                "已授权的客户端都已撤销或过期，授权无法继续使用。",
            )
            .with_evidence("grants")
            .recovery("重新配对客户端后再次授权")
        } else {
            let mut status = DimensionStatus::new(
                STATE_UNCHECKED,
                "尚未检查",
                "已授权，但还没有通过本机代理验证或真实调用记录。",
            )
            .with_evidence("grants");
            if restricted {
                status.detail = "已授权。此连接仍有拒绝规则或审批要求，这些限制继续生效。".into();
                status.state = STATE_RESTRICTED.to_owned();
                status.label = "已授权 · 有限制".to_owned();
            }
            let evidence = Vault::evidence_for(details, DIMENSION_API);
            if let Some(evidence) = evidence
                .as_ref()
                .filter(|e| !e.context.is_empty() && e.context != fingerprint)
            {
                status = DimensionStatus::new(
                    STATE_STALE,
                    "检查结果已过期",
                    "检查之后账号、地址或环境已变化，旧结果不再可信。",
                )
                .with_evidence("check")
                .checked(evidence.checked_at.clone())
                .errored("account_context_changed", "重新检查");
            } else if let Some(evidence) = evidence {
                let mut mapped = api_from_evidence(&evidence);
                if let Some(scope) = evidence.scope.as_deref().filter(|s| !s.is_empty()) {
                    mapped.detail = format!("{}（作用域：{scope}）", mapped.detail);
                }
                status = mapped
                    .with_evidence("check")
                    .checked(evidence.checked_at.clone());
                if let Some(code) = &evidence.error_code {
                    status = status.errored(code, recovery_for(code));
                }
            } else if let Some(usage) = last_usage_evidence(alias, audit) {
                status = usage.with_evidence("usage");
            }
            status
        }
    };

    // Dimension 4: browser capability. Gated behind its own contract; the
    // API authorization never migrates into it. Real end-to-end verification
    // is a separate manual acceptance step, so an enabled connection still
    // reports "尚未检查" instead of "可用".
    let web = if personal {
        DimensionStatus::new(STATE_NOT_AVAILABLE, "不适用", "个人密码没有网页操作能力。")
            .with_evidence("policy")
    } else if !details.web_enabled {
        DimensionStatus::new(
            STATE_NOT_AVAILABLE,
            "尚未开启",
            "AI 网页操作未开启；已保存的登录会话仅供接口调用。",
        )
        .with_evidence("policy")
    } else {
        DimensionStatus::new(
            STATE_UNCHECKED,
            "已开启 · 尚未检查",
            "网页操作能力已开启；请在真实页面验证后确认可用。",
        )
        .with_evidence("policy")
    };

    // Dimension 5: client authorization state for this connection.
    let clients_status = if personal {
        DimensionStatus::new(STATE_NOT_AVAILABLE, "不适用", "个人密码不做客户端授权。")
            .with_evidence("policy")
    } else if active_clients == 0 && invalid_clients == 0 {
        DimensionStatus::new(STATE_NONE, "未授权", "没有客户端被允许使用此连接。")
            .with_evidence("grants")
    } else if invalid_clients > 0 && active_clients == 0 {
        DimensionStatus::new(
            STATE_INVALID,
            "客户端已失效",
            "曾经授权的客户端已全部撤销或过期。",
        )
        .with_evidence("grants")
        .recovery("重新配对后再次授权")
    } else {
        let mut status = DimensionStatus::new(
            STATE_GRANTED,
            format!("{active_clients} 个客户端已授权"),
            "授权持续到撤销；拒绝规则继续生效。",
        )
        .with_evidence("grants");
        if invalid_clients > 0 {
            status.detail = format!(
                "{} 个客户端已授权，另有 {} 个已撤销或过期。",
                active_clients, invalid_clients
            );
        }
        status
    };

    ConnectionStatus {
        alias: alias.to_owned(),
        credential,
        identity,
        api,
        web,
        clients: clients_status,
    }
}

/// Count active/invalid harness grants for a connection and whether any
/// explicit restriction (deny rule or approval requirement) still applies.
/// A harness counts as active only when it can actually authenticate:
/// legacy token harnesses have no paired client, revoked or expired
/// pairings invalidate the grant even though the profile row remains.
/// Returns (active, invalid, restricted).
fn grant_summary(
    alias: &str,
    harnesses: &[crate::HarnessSummary],
    clients: &[crate::ClientSummary],
) -> (usize, usize, bool) {
    let mut active = 0;
    let mut invalid = 0;
    let mut restricted = false;
    for profile in harnesses {
        let Ok(policy) = crate::Policy::from_json(&profile.policy) else {
            continue;
        };
        let covers = policy.default_action == crate::DefaultAction::Allow
            || policy.allow.iter().any(|rule| {
                rule.site == alias && !crate::vault::is_expired(rule.expires_at.as_deref())
            });
        if !covers {
            continue;
        }
        let profile_valid = profile.revoked_at.is_none()
            && !crate::vault::is_expired(profile.expires_at.as_deref());
        let identities: Vec<_> = clients
            .iter()
            .filter(|client| client.harness == profile.name)
            .collect();
        let identity_valid = if identities.is_empty() {
            // Legacy token identity; revocation lives on the harness row.
            profile_valid
        } else {
            identities.iter().any(|client| {
                client.paired
                    && client.revoked_at.is_none()
                    && !crate::vault::is_expired(client.expires_at.as_deref())
            })
        };
        if !profile_valid || !identity_valid {
            invalid += 1;
            continue;
        }
        active += 1;
        if policy
            .deny
            .iter()
            .any(|rule| rule.site == alias || rule.site == "*")
            || policy
                .allow
                .iter()
                .any(|rule| rule.site == alias && rule.require_approval == Some(true))
            || !policy.approval.required_for.is_empty()
        {
            restricted = true;
        }
    }
    (active, invalid, restricted)
}

/// Last real AI usage from the audit log. CLI self-checks never write
/// business-shaped entries, so this is genuine usage evidence, not a
/// substitute for the identity check.
fn last_usage_evidence(alias: &str, audit: &[crate::AuditEntry]) -> Option<DimensionStatus> {
    let entry = audit
        .iter()
        .find(|entry| entry.site.as_deref() == Some(alias) && entry.status_code.is_some())?;
    let status_code = u16::try_from(entry.status_code?).ok()?;
    let checked_at = entry.ts.clone();
    let detail = format!(
        "最近真实 AI 调用（{} {}）返回 {}。",
        entry.method.as_deref().unwrap_or("?"),
        entry.path.as_deref().unwrap_or("/"),
        status_code
    );
    Some(match status_code {
        200..=399 => DimensionStatus::new(STATE_READY, "最近调用正常", detail).checked(checked_at),
        401 => DimensionStatus::new(STATE_UNAUTHORIZED, "最近调用被拒绝(401)", detail)
            .checked(checked_at)
            .errored("session_expired", "重新登录或更新凭据"),
        403 => DimensionStatus::new(STATE_FORBIDDEN, "最近调用权限不足(403)", detail)
            .checked(checked_at)
            .errored("explicit_deny", "确认服务端账号权限，403 不一定是凭据过期"),
        429 => DimensionStatus::new(STATE_RATE_LIMITED, "最近调用被限流(429)", detail)
            .checked(checked_at)
            .errored("rate_limited", "稍后重试"),
        _ => {
            DimensionStatus::new(STATE_INVALID_RESPONSE, "最近调用异常", detail).checked(checked_at)
        }
    })
}

fn identity_from_evidence(evidence: &CheckEvidence) -> DimensionStatus {
    let mut status = match evidence.state.as_str() {
        "connected" | "verified" => {
            let mut status = DimensionStatus::new(
                STATE_VERIFIED,
                "身份已验证",
                "远端只读身份接口确认了此账号。",
            );
            if let Some(account) = evidence.account.as_deref().filter(|a| !a.is_empty()) {
                status.detail = format!("远端确认账号身份：{account}。");
            }
            status
        }
        "expired" | "session_expired" => {
            DimensionStatus::new(STATE_EXPIRED, "会话已过期", "远端会话或令牌已失效。")
        }
        "unauthorized" => {
            DimensionStatus::new(STATE_UNAUTHORIZED, "身份验证失败(401)", "远端拒绝此凭据。")
        }
        "forbidden" => DimensionStatus::new(
            STATE_FORBIDDEN,
            "权限不足(403)",
            "凭据有效，但此账号没有访问该接口的权限。",
        ),
        "rate_limited" => {
            DimensionStatus::new(STATE_RATE_LIMITED, "被限流(429)", "检查请求被限流。")
        }
        "timeout" => DimensionStatus::new(STATE_TIMEOUT, "检查超时", "远端在时限内未返回。"),
        "network_error" => DimensionStatus::new(
            STATE_NETWORK_ERROR,
            "网络异常",
            "检查请求未能到达远端服务。",
        ),
        "invalid_response" | "invalid_state" => DimensionStatus::new(
            STATE_INVALID_RESPONSE,
            "响应无法识别",
            "远端返回了无法解析的身份信息。",
        ),
        "account_mismatch" => DimensionStatus::new(
            STATE_STALE,
            "账号已变化",
            "远端返回的账号与连接绑定的账号不一致。",
        ),
        other => DimensionStatus::new(
            STATE_INVALID_RESPONSE,
            "状态未知",
            format!("检查返回了未知状态({other})。"),
        ),
    };
    status = status.with_evidence("check");
    if !evidence.checked_at.is_empty() {
        status = status.checked(evidence.checked_at.clone());
    }
    if let Some(account) = evidence.account.as_deref().filter(|a| !a.is_empty()) {
        if status.state == STATE_VERIFIED {
            status.detail = format!("{} 账号：{account}。", status.detail.trim_end_matches('。'));
        }
    }
    if let Some(code) = &evidence.error_code {
        status = status.errored(code, recovery_for(code));
    } else if status.state != STATE_VERIFIED {
        status = status.errored(&evidence.state, recovery_for(&evidence.state));
    }
    if let Some(scope) = evidence.scope.as_deref().filter(|s| !s.is_empty()) {
        status.detail = format!("{}（作用域：{scope}）", status.detail);
    }
    status
}

fn api_from_evidence(evidence: &CheckEvidence) -> DimensionStatus {
    let mut status = match evidence.state.as_str() {
        "ready" | "connected" | "verified" => DimensionStatus::new(
            STATE_READY,
            "本机检查通过",
            "通过本机代理的只读检查请求成功返回。",
        ),
        "unauthorized" => DimensionStatus::new(
            STATE_UNAUTHORIZED,
            "检查被拒绝(401)",
            "远端返回 401，凭据可能已失效。",
        ),
        "forbidden" => DimensionStatus::new(
            STATE_FORBIDDEN,
            "权限不足(403)",
            "远端返回 403；这不代表凭据过期，可能是账号权限不足。",
        ),
        "rate_limited" => {
            DimensionStatus::new(STATE_RATE_LIMITED, "被限流(429)", "检查请求被限流。")
        }
        "timeout" => DimensionStatus::new(STATE_TIMEOUT, "检查超时", "远端在时限内未返回。"),
        "network_error" => DimensionStatus::new(
            STATE_NETWORK_ERROR,
            "网络异常",
            "检查请求未能到达远端服务。",
        ),
        "invalid_response" => DimensionStatus::new(
            STATE_INVALID_RESPONSE,
            "响应无法识别",
            "检查请求返回了无法解析的内容。",
        ),
        other => DimensionStatus::new(
            STATE_INVALID_RESPONSE,
            "状态未知",
            format!("检查返回了未知状态({other})。"),
        ),
    };
    if status.state != STATE_READY {
        if let Some(code) = &evidence.error_code {
            status = status.errored(code, recovery_for(code));
        } else {
            status = status.errored(&evidence.state, recovery_for(&evidence.state));
        }
    }
    status
}

/// Stable recovery actions. Error text never contains credential material.
pub fn recovery_for(code: &str) -> &'static str {
    match code {
        "session_expired" | "expired" => "重新登录或更新凭据",
        "unauthorized" => "更新凭据或重新登录",
        "forbidden" => "确认服务端账号权限；403 不一定是凭据过期",
        "explicit_deny" => "如需允许，先在 AI 工具中移除对应的拒绝规则",
        "pending_approval" => "等待用户在 pman 桌面批准该请求",
        "network_error" => "检查网络连接后重试",
        "timeout" => "稍后重新检查",
        "rate_limited" => "等待限流窗口结束后重试",
        "service_paused" => "在 pman 桌面恢复 AI 服务",
        "management_locked" => "解锁管理界面；这不影响已授权的 AI 调用",
        "account_context_changed" => "重新确认账号与地址后重新检查或授权",
        "not_paired" => "在 pman 桌面配对此 AI 客户端",
        "harness_invalid" => "重新配对客户端后再授权",
        "invalid_response" => "重新检查；如果持续出现，确认服务地址正确",
        "response_blocked" => "检查结果疑似包含凭据，已阻止显示；重新登录后再试",
        _ => "重新检查连接",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vault_with_connection() -> (tempfile::TempDir, Vault, std::net::SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                format!("http://{address}"),
                "api_token",
                json!({"token":"synthetic-only"}),
            ))
            .unwrap();
        (temp, vault, address)
    }

    fn grant_client(vault: &mut Vault, id: &str) {
        vault
            .pair_client_for(id, "generic", id, id, &"a".repeat(64))
            .unwrap();
        vault.add_allow_rule(id, "api", "GET", "/**").unwrap();
        vault
            .update_details("api", json!({"ai_enabled":true}))
            .unwrap();
    }

    #[test]
    fn saved_but_unchecked_reports_unchecked_dimensions_without_inventing_evidence() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.credential.state, STATE_SAVED);
        assert_eq!(status.identity.state, STATE_UNCHECKED);
        assert_eq!(status.identity.label, "尚未检查");
        assert_eq!(status.api.state, STATE_UNCHECKED);
        assert_eq!(status.api.label, "尚未检查");
        assert_eq!(status.web.state, STATE_NOT_AVAILABLE);
        assert_eq!(status.clients.state, STATE_GRANTED);
        assert_eq!(status.clients.checked_at, None);
    }

    #[test]
    fn oauth_placeholder_is_reported_as_waiting_for_login_not_as_a_saved_credential() {
        let (_temp, mut vault, _address) = vault_with_connection();
        vault
            .update_details("api", json!({"extra":{"oauth_pending":true}}))
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.credential.state, STATE_UNCHECKED);
        assert_eq!(status.credential.label, "等待 OAuth 登录");
        assert_eq!(status.credential.recovery, Some("继续 OAuth 登录".into()));
    }

    #[test]
    fn proxy_reached_but_remote_401_is_distinct_from_unchecked() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        vault
            .record_check_evidence(
                "api",
                DIMENSION_IDENTITY,
                CheckEvidence {
                    state: "unauthorized".into(),
                    checked_at: "2026-09-19T10:00:00".into(),
                    message: "远端返回 401".into(),
                    error_code: Some("session_expired".into()),
                    ..CheckEvidence::default()
                },
            )
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, STATE_UNAUTHORIZED);
        assert_eq!(status.identity.label, "身份验证失败(401)");
        assert_eq!(status.identity.recovery, Some("重新登录或更新凭据".into()));
        // A failed identity check must not claim API capability.
        assert_eq!(status.api.state, STATE_UNCHECKED);
        assert_ne!(status.identity.state, STATE_UNCHECKED);
    }

    #[test]
    fn authorized_but_revoked_client_is_distinct_and_requires_repair() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        vault.revoke_client("client-one").unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.clients.state, STATE_INVALID);
        assert_eq!(status.api.state, STATE_CLIENT_INVALID);
        assert!(status.api.recovery.is_some());
        assert_ne!(status.clients.state, STATE_GRANTED);
    }

    #[test]
    fn stale_evidence_after_account_change_never_displays_as_current() {
        let (_temp, mut vault, _address) = vault_with_connection();
        vault
            .record_check_evidence(
                "api",
                DIMENSION_IDENTITY,
                CheckEvidence {
                    state: "verified".into(),
                    checked_at: "2026-09-19T10:00:00".into(),
                    ..CheckEvidence::default()
                },
            )
            .unwrap();
        vault
            .update_details("api", json!({"account":"different-user"}))
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, STATE_STALE);
        assert_eq!(
            status.identity.error_code,
            Some("account_context_changed".into())
        );
    }

    #[test]
    fn usage_evidence_comes_from_real_calls_and_is_overridden_by_fresher_checks() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        // A real authorized call left an audit record (sanitized routing only).
        vault
            .add_audit(&crate::AuditEntryInput {
                harness: "client-one".into(),
                site: Some("api".into()),
                method: Some("GET".into()),
                path: Some("/data".into()),
                status_code: Some(200),
                ..crate::AuditEntryInput::default()
            })
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.api.state, STATE_READY);
        assert_eq!(status.api.evidence, Some("usage".into()));
        assert!(status.api.detail.contains("最近真实 AI 调用"));
        // An explicit local check with a declared scope takes precedence.
        vault
            .record_check_evidence(
                "api",
                DIMENSION_API,
                CheckEvidence {
                    state: "unauthorized".into(),
                    checked_at: crate::vault::now(),
                    scope: Some("GET / 只读检查".into()),
                    error_code: Some("unauthorized".into()),
                    ..CheckEvidence::default()
                },
            )
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.api.state, STATE_UNAUTHORIZED);
        assert_eq!(status.api.evidence, Some("check".into()));
        assert!(status.api.detail.contains("作用域"));
    }

    #[test]
    fn restricted_grants_are_visible_not_silent() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        vault
            .set_policy(
                "client-one",
                json!({
                    "allow":[{"site":"api","methods":["GET"],"paths":["/**"],"require_approval":false}],
                    "deny":[{"site":"api","methods":["DELETE"],"paths":["/danger"]}]
                }),
            )
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.api.state, STATE_RESTRICTED);
        assert!(status.api.detail.contains("限制"));
    }

    #[test]
    fn paused_and_ungranted_states_are_distinguishable() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        vault
            .update_details("api", json!({"ai_enabled":false}))
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.api.state, STATE_PAUSED);
        assert_eq!(status.clients.state, STATE_GRANTED);
        vault.revoke_connection_grants("api").unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.api.state, STATE_NOT_GRANTED);
        assert_eq!(status.api.label, "未授权 AI");
    }

    #[test]
    fn personal_password_never_claims_ai_or_web_capability() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "personal",
                "",
                "password",
                json!({"password":"synthetic-only"}),
            ))
            .unwrap();
        let status = vault.connection_status("personal").unwrap();
        assert_eq!(status.credential.state, STATE_SAVED);
        assert_eq!(status.identity.state, STATE_NOT_AVAILABLE);
        assert_eq!(status.api.state, STATE_NOT_AVAILABLE);
        assert_eq!(status.web.state, STATE_NOT_AVAILABLE);
        assert_eq!(status.clients.state, STATE_NOT_AVAILABLE);
    }

    #[test]
    fn updating_credentials_clears_stale_check_evidence() {
        let (_temp, mut vault, _address) = vault_with_connection();
        grant_client(&mut vault, "client-one");
        vault
            .record_check_evidence(
                "api",
                DIMENSION_IDENTITY,
                CheckEvidence {
                    state: "verified".into(),
                    checked_at: crate::vault::now(),
                    ..CheckEvidence::default()
                },
            )
            .unwrap();
        assert_eq!(
            vault.connection_status("api").unwrap().identity.state,
            STATE_VERIFIED
        );
        vault
            .rotate_secret("api", json!({"token": "brand-new-synthetic"}))
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(
            status.identity.state, STATE_UNCHECKED,
            "更换凭据后旧身份证据必须清除"
        );
        assert_eq!(status.identity.label, "尚未检查");
    }

    #[test]
    fn legacy_authflow_evidence_is_readable_through_the_contract() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "authflow",
                "https://authflow.example",
                "login",
                json!({"session_value":"synthetic-only"}),
            ))
            .unwrap();
        // Write only the legacy keys, as the previous version did.
        vault
            .update_details(
                "authflow",
                json!({"extra":{"status":"connected","checked_at":"2026-09-19T09:00:00"}}),
            )
            .unwrap();
        let status = vault.connection_status("authflow").unwrap();
        assert_eq!(status.identity.state, STATE_VERIFIED);
        assert_eq!(
            status.identity.checked_at,
            Some("2026-09-19T09:00:00".into())
        );
        assert_eq!(status.identity.evidence, Some("check".into()));
    }

    #[test]
    fn old_vaults_open_without_gaining_capabilities_or_losing_policies() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(temp.path()).unwrap();
        vault.create("synthetic-password").unwrap();
        vault
            .add_site(crate::SiteInput::new(
                "api",
                "https://example.test",
                "api_token",
                json!({"token":"synthetic-only"}),
            ))
            .unwrap();
        vault.ensure_harness("legacy").unwrap();
        // A pre-contract scoped rule must survive verbatim.
        vault
            .set_policy(
                "legacy",
                json!({"allow":[{"site":"api","methods":["GET"],"paths":["/read"]}]}),
            )
            .unwrap();
        vault
            .conn
            .execute(
                "INSERT INTO connection_details(alias,details_json) VALUES('api','{\"extra\":{}}')
                 ON CONFLICT(alias) DO UPDATE SET details_json='{\"extra\":{}}'",
                [],
            )
            .unwrap();
        let status = vault.connection_status("api").unwrap();
        assert_eq!(status.identity.state, STATE_UNCHECKED);
        assert_eq!(status.web.state, STATE_NOT_AVAILABLE);
        // Legacy partial rules are not silently promoted to whole-connection grants.
        let policy = vault.get_policy("legacy").unwrap();
        assert_eq!(
            policy["allow"][0]["paths"],
            json!(["/read"]),
            "旧范围规则必须原样保留"
        );
        assert!(!policy["allow"][0]
            .as_object()
            .unwrap()
            .contains_key("require_approval"));
    }

    #[test]
    fn evidence_recording_does_not_invalidate_inflight_requests() {
        let (_temp, mut vault, _address) = vault_with_connection();
        let before = vault.generation();
        vault
            .record_check_evidence(
                "api",
                DIMENSION_IDENTITY,
                CheckEvidence {
                    state: "verified".into(),
                    checked_at: crate::vault::now(),
                    ..CheckEvidence::default()
                },
            )
            .unwrap();
        assert_eq!(
            vault.generation(),
            before,
            "检查只是记录证据，不能使已授权请求失效"
        );
    }
}
