//! Harness policy evaluation shared by the CLI, daemon and desktop commands.

use crate::HttpRequest;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid harness policy: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default, alias = "default")]
    pub default_action: DefaultAction,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub deny: Vec<AllowRule>,
    #[serde(default)]
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub approval: ApprovalPolicy,
    #[serde(default)]
    pub redact: RedactionPolicy,
    /// Independent browser-capability grants (BROWSER-CONTRACT.md). Old
    /// policies without this field default to empty: API authorization never
    /// migrates into web capability.
    #[serde(default)]
    pub web: Vec<WebRule>,
}

/// Per-client, per-connection browser capability. Absent = no web access.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct WebRule {
    pub site: String,
    /// Allowed actions: open, summary, click, fill, wait, close.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Allowed page origins; an action outside them is denied.
    #[serde(default)]
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowRule {
    pub site: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub require_approval: Option<bool>,
    /// Optional business capability. Rules without it remain compatible with
    /// existing callers; rules with it cannot be used by an unlabelled request.
    #[serde(default)]
    pub capability: Option<String>,
    /// Flat request-field constraints. Every configured key must be present and
    /// match at least one glob. Unlisted keys remain allowed for compatibility.
    #[serde(default)]
    pub constraints: RequestConstraints,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RequestConstraints {
    #[serde(default)]
    pub query: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub json_body: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub form: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimit {
    #[serde(default, alias = "req_per_min")]
    pub req_per_min: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApprovalPolicy {
    #[serde(default)]
    pub required_for: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPolicy {
    #[serde(default = "default_strip_headers")]
    pub strip_headers: Vec<String>,
    #[serde(default = "default_json_keys")]
    pub json_keys: Vec<String>,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            strip_headers: default_strip_headers(),
            json_keys: default_json_keys(),
            max_response_bytes: default_max_response_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: String::new(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

impl Policy {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, PolicyError> {
        let policy: Self = serde_json::from_value(value.clone())
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        for rule in policy.web.iter() {
            if rule.site.is_empty()
                || rule.site.chars().count() > 128
                || rule.actions.is_empty()
                || rule
                    .actions
                    .iter()
                    .any(|a| !crate::browser::WEB_ACTIONS.contains(&a.as_str()))
                || rule.origins.is_empty()
                || rule.origins.iter().any(|o| {
                    o.is_empty()
                        || o.len() > 256
                        || crate::browser::normalize_web_origin(o).is_err()
                })
            {
                return Err(PolicyError::Invalid("invalid web rule".into()));
            }
        }
        for rule in policy.allow.iter().chain(policy.deny.iter()) {
            if rule.capability.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric()
                            || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
                    })
            }) {
                return Err(PolicyError::Invalid("invalid capability id".into()));
            }
            for fields in [
                &rule.constraints.query,
                &rule.constraints.json_body,
                &rule.constraints.form,
            ] {
                if fields.len() > 64
                    || fields.iter().any(|(key, patterns)| {
                        key.is_empty()
                            || key.len() > 128
                            || patterns.is_empty()
                            || patterns.len() > 64
                            || patterns.iter().any(|pattern| pattern.len() > 512)
                    })
                {
                    return Err(PolicyError::Invalid(
                        "constraint keys and value patterns cannot be empty".into(),
                    ));
                }
            }
        }
        Ok(policy)
    }

    pub fn authorize(&self, site: &str, method: &str, path: &str) -> Decision {
        self.authorize_request(&HttpRequest {
            site: site.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        })
    }

    pub fn authorize_request(&self, request: &HttpRequest) -> Decision {
        let site = &request.site;
        let method = request.method.to_ascii_uppercase();
        let path = &request.path;
        if self.explicitly_denied_request(request) {
            return Decision::deny("explicit_deny");
        }
        for rule in &self.allow {
            if crate::vault::is_expired(rule.expires_at.as_deref()) {
                continue;
            }
            if rule.site != site.as_str()
                || !rule
                    .methods
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(&method))
            {
                continue;
            }
            if (rule.paths.is_empty() || rule.paths.iter().any(|pattern| glob_match(pattern, path)))
                && rule_matches_request(rule, request)
            {
                return Decision::allow();
            }
        }
        if self.default_action == DefaultAction::Allow {
            return Decision::allow();
        }
        Decision::deny(format!("策略拒绝：{method} {path} @ {site}"))
    }

    pub fn explicitly_denied(&self, site: &str, method: &str, path: &str) -> bool {
        self.explicitly_denied_request(&HttpRequest {
            site: site.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        })
    }

    pub fn explicitly_denied_request(&self, request: &HttpRequest) -> bool {
        let site = &request.site;
        let method = &request.method;
        let path = &request.path;
        self.deny.iter().any(|rule| {
            (rule.site == site.as_str() || rule.site == "*")
                && rule
                    .methods
                    .iter()
                    .any(|m| m == "*" || m.eq_ignore_ascii_case(method))
                && (rule.paths.is_empty() || rule.paths.iter().any(|p| glob_match(p, path)))
                && rule_matches_request(rule, request)
        })
    }

    pub fn approval_required(&self, method: &str) -> bool {
        self.approval
            .required_for
            .iter()
            .any(|item| item.eq_ignore_ascii_case(method))
    }

    /// A reusable consent changes only its matching path/method scope.
    pub fn approval_required_for(&self, site: &str, method: &str, path: &str) -> bool {
        self.approval_required_for_request(&HttpRequest {
            site: site.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            capability: None,
            query: None,
            json_body: None,
            form: None,
        })
    }

    pub fn approval_required_for_request(&self, request: &HttpRequest) -> bool {
        let site = &request.site;
        let method = &request.method;
        let path = &request.path;
        let matched = self
            .allow
            .iter()
            .filter(|r| {
                r.site == site.as_str()
                    && !crate::vault::is_expired(r.expires_at.as_deref())
                    && r.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
                    && (r.paths.is_empty() || r.paths.iter().any(|p| glob_match(p, path)))
                    && rule_matches_request(r, request)
            })
            .collect::<Vec<_>>();
        // A persistent approval is stored as one exact method/path exemption.
        // It may override a broader "always ask" rule, but never an explicit
        // deny (checked before this method by the broker).
        if matched.iter().any(|r| {
            r.require_approval == Some(false)
                && r.methods.len() == 1
                && r.methods[0].eq_ignore_ascii_case(method)
                && r.paths.len() == 1
                && r.paths[0] == path.as_str()
        }) {
            return false;
        }
        if matched.iter().any(|r| r.require_approval == Some(true)) {
            return true;
        }
        if matched.iter().any(|r| r.require_approval == Some(false)) {
            return false;
        }
        self.approval_required(method)
    }
}

fn rule_matches_request(rule: &AllowRule, request: &HttpRequest) -> bool {
    if let Some(expected) = rule.capability.as_deref() {
        if request.capability.as_deref() != Some(expected) {
            return false;
        }
    }
    constraints_match(&rule.constraints.query, request.query.as_ref())
        && constraints_match(&rule.constraints.json_body, request.json_body.as_ref())
        && constraints_match(&rule.constraints.form, request.form.as_ref())
}

fn constraints_match(
    constraints: &BTreeMap<String, Vec<String>>,
    actual: Option<&serde_json::Value>,
) -> bool {
    if constraints.is_empty() {
        return true;
    }
    let Some(actual) = actual.and_then(serde_json::Value::as_object) else {
        return false;
    };
    constraints.iter().all(|(key, patterns)| {
        actual.get(key).is_some_and(|value| {
            let rendered = match value {
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Number(value) => value.to_string(),
                serde_json::Value::Bool(value) => value.to_string(),
                serde_json::Value::Null => "null".to_owned(),
                _ => return false,
            };
            patterns
                .iter()
                .any(|pattern| glob_match(pattern, &rendered))
        })
    })
}

/// Sliding one-minute window, keyed by harness name.
#[derive(Default)]
pub struct RateLimiter {
    events: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn check(&self, name: &str, per_minute: u32) -> Result<(), String> {
        if per_minute == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut events = self
            .events
            .lock()
            .map_err(|_| "限流器状态锁定失败".to_owned())?;
        let queue = events.entry(name.to_owned()).or_default();
        while queue
            .front()
            .is_some_and(|event| now.duration_since(*event) > Duration::from_secs(60))
        {
            queue.pop_front();
        }
        if queue.len() >= per_minute as usize {
            return Err(format!("超过配额 {per_minute} 次/分钟"));
        }
        queue.push_back(now);
        Ok(())
    }
}

pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut dp = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    dp[pattern.len()][text.len()] = true;
    for p in (0..pattern.len()).rev() {
        for t in (0..=text.len()).rev() {
            dp[p][t] = if pattern[p] == '*' && p + 1 < pattern.len() && pattern[p + 1] == '*' {
                // A double star crosses path separators, including zero characters.
                dp[p + 2][t] || (t < text.len() && dp[p][t + 1])
            } else if pattern[p] == '*' {
                dp[p + 1][t] || (t < text.len() && text[t] != '/' && dp[p][t + 1])
            } else {
                t < text.len() && pattern[p] == text[t] && dp[p + 1][t + 1]
            };
        }
    }
    dp[0][0]
}

fn default_strip_headers() -> Vec<String> {
    [
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "session_value",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_json_keys() -> Vec<String> {
    [
        "token",
        "password",
        "passwd",
        "secret",
        "cookie",
        "authorization",
        "api_key",
        "session_value",
        "session_id",
        "sessionid",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_max_response_bytes() -> usize {
    524_288
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            allow: vec![AllowRule {
                site: "gitlab".to_owned(),
                methods: vec!["GET".to_owned()],
                paths: vec!["/api/v4/projects/**".to_owned()],
                expires_at: None,
                require_approval: None,
                capability: None,
                constraints: RequestConstraints::default(),
            }],
            ..Policy::default()
        }
    }

    #[test]
    fn default_deny_and_glob_paths() {
        let policy = policy();
        assert!(
            policy
                .authorize("gitlab", "get", "/api/v4/projects/42/pipelines")
                .allowed
        );
        assert!(
            !policy
                .authorize("gitlab", "POST", "/api/v4/projects/42")
                .allowed
        );
        assert!(!policy.authorize("gitlab", "GET", "/api/v4/users").allowed);
    }

    #[test]
    fn single_star_does_not_cross_path_separator() {
        let policy = Policy {
            allow: vec![AllowRule {
                site: "s".to_owned(),
                methods: vec!["GET".to_owned()],
                paths: vec!["/a/*/c".to_owned()],
                expires_at: None,
                require_approval: None,
                capability: None,
                constraints: RequestConstraints::default(),
            }],
            ..Policy::default()
        };
        assert!(policy.authorize("s", "GET", "/a/b/c").allowed);
        assert!(!policy.authorize("s", "GET", "/a/b/d/c").allowed);
    }

    #[test]
    fn capability_and_request_values_are_enforced_together() {
        let policy = Policy::from_json(&serde_json::json!({"allow":[{
            "site":"jenkins",
            "methods":["POST"],
            "paths":["/build"],
            "capability":"jenkins.build.test",
            "constraints":{"query":{"service":["web-*"],"environment":["test"]}}
        }]}))
        .unwrap();
        let request = HttpRequest {
            site: "jenkins".into(),
            method: "POST".into(),
            path: "/build".into(),
            capability: Some("jenkins.build.test".into()),
            query: Some(serde_json::json!({"service":"web-api","environment":"test"})),
            json_body: None,
            form: None,
        };
        assert!(policy.authorize_request(&request).allowed);
        let wrong_capability = HttpRequest {
            capability: Some("jenkins.release".into()),
            ..request.clone()
        };
        assert!(!policy.authorize_request(&wrong_capability).allowed);
        let wrong_environment = HttpRequest {
            query: Some(serde_json::json!({"service":"web-api","environment":"prod"})),
            ..request
        };
        assert!(!policy.authorize_request(&wrong_environment).allowed);
    }

    #[test]
    fn explicit_default_allow_covers_unmatched_requests() {
        let policy = Policy {
            default_action: DefaultAction::Allow,
            ..Policy::default()
        };
        assert!(policy.authorize("s", "GET", "/any/path").allowed);
    }

    #[test]
    fn rate_limiter_uses_harness_window() {
        let limiter = RateLimiter::default();
        assert!(limiter.check("codex", 2).is_ok());
        assert!(limiter.check("codex", 2).is_ok());
        assert!(limiter.check("codex", 2).is_err());
        assert!(limiter.check("claude", 1).is_ok());
    }
    #[test]
    fn expired_grants_and_explicit_denies_fail_closed() {
        let policy=Policy::from_json(&serde_json::json!({"allow":[{"site":"s","methods":["POST"],"paths":["/**"],"expires_at":"2001-01-01T00:00:00Z"}]})).unwrap();
        assert!(!policy.authorize("s", "POST", "/query").allowed);
        let policy=Policy::from_json(&serde_json::json!({"default_action":"allow","deny":[{"site":"s","methods":["GET"],"paths":["/delete"]}]})).unwrap();
        assert!(!policy.authorize("s", "GET", "/delete").allowed);
        assert!(policy.authorize("s", "POST", "/query").allowed);
    }
    #[test]
    fn reusable_query_grant_does_not_waive_other_post_approvals() {
        let p=Policy::from_json(&serde_json::json!({"approval":{"required_for":["POST"]},"allow":[{"site":"s","methods":["POST"],"paths":["/**"]},{"site":"s","methods":["POST"],"paths":["/query"],"require_approval":false}]})).unwrap();
        assert!(!p.approval_required_for("s", "POST", "/query"));
        assert!(p.approval_required_for("s", "POST", "/danger"));
    }
}
