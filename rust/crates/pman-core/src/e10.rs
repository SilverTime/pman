//! E10 provider adapter.
//!
//! The authorization orchestration is shared with other connections, but E10
//! uses a provider-specific session check and request envelope.  Cookies stay
//! inside the broker; only safe account metadata crosses the UI boundary.

use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, time::Duration};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const JSON_LIMIT: u64 = 512 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum E10Error {
    #[error("E10 origin must be an HTTPS origin (HTTP is allowed only on loopback)")]
    InvalidOrigin,
    #[error("invalid E10 agent type")]
    InvalidAgentType,
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
            Self::Expired => "expired",
            Self::Forbidden => "forbidden",
            Self::Network => "network_error",
            Self::InvalidResponse => "invalid_response",
            Self::AccountMismatch => "account_mismatch",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

pub fn normalize_origin(origin: &str) -> Result<String, E10Error> {
    let parsed = Url::parse(origin.trim()).map_err(|_| E10Error::InvalidOrigin)?;
    let loopback = parsed.host_str().is_some_and(|host| {
        host == "localhost" || host == "127.0.0.1" || host == "[::1]"
    });
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

fn valid_agent(agent: &str) -> bool {
    !agent.is_empty()
        && agent.len() <= 64
        && agent
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
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
    // Some E10 gateways prepend a UTF-8 BOM. It is not credential material
    // and can be removed before parsing the otherwise normal JSON envelope.
    let body = body.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&body);
    let value: Value = serde_json::from_slice(body).map_err(|_| E10Error::InvalidResponse)?;
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

/// Build the E10 request envelope from host-bound cookies.
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
    let mut pairs = crate::http_proxy::cookie_pairs(secret, target)
        .map_err(|_| E10Error::InvalidResponse)?;
    let sid = pairs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("ETEAMSID"))
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
        .ok_or(E10Error::Expired)?;
    pairs.retain(|(name, _)| {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "agenttype" | "isagent"
        )
    });
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

/// Detect a browser-captured E10 session that is still stored under the
/// generic `login`/`cookie_jar` type from an older vault. This lets migrated
/// connections keep the E10 request envelope without exposing or rewriting
/// their secret in the UI.
pub(crate) fn looks_like_session(secret: &Value, target: &Url) -> bool {
    let Some(origin) = secret.get("origin").and_then(Value::as_str) else {
        return false;
    };
    let target_origin = target.origin().ascii_serialization();
    if normalize_origin(origin).ok().as_deref() != Some(target_origin.as_str()) {
        return false;
    }
    if secret.get("agent_type").and_then(Value::as_str).is_some() {
        return true;
    }
    crate::http_proxy::cookie_pairs(secret, target)
        .map(|pairs| pairs.iter().any(|(name, value)| name.eq_ignore_ascii_case("ETEAMSID") && !value.is_empty()))
        .unwrap_or(false)
}

/// Check a browser-captured E10 session without returning its credentials.
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
    let environment_id = format!("e10-{}", &hex::encode(Sha256::digest(origin.as_bytes()))[..24]);
    let account_id = format!(
        "account-{}",
        &hex::encode(Sha256::digest(format!("{origin}\0{tenant_key}\0{user_id}").as_bytes()))[..24]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn e10_origin_is_strict() {
        assert_eq!(
            normalize_origin("https://E10.EXAMPLE:443/").unwrap(),
            "https://e10.example"
        );
        assert_eq!(normalize_origin("https://e10.example/app"), Err(E10Error::InvalidOrigin));
        assert_eq!(normalize_origin("http://e10.example"), Err(E10Error::InvalidOrigin));
    }

    #[test]
    fn request_auth_requires_host_bound_eteamsid_and_adds_agent_headers() {
        let target = Url::parse("https://e10.example/api/check").unwrap();
        let secret = json!({
            "origin": "https://e10.example",
            "agent_type": "Codex",
            "cookies": [{"name":"ETEAMSID","value":"synthetic","domain":"e10.example","path":"/","host_only":true}]
        });
        let (sid, cookie, agent) = request_auth(&secret, &target).unwrap();
        assert_eq!(sid, "synthetic");
        assert!(cookie.contains("ETEAMSID=synthetic"));
        assert!(cookie.contains("agentType=Codex"));
        assert!(cookie.contains("isAgent=true"));
        assert_eq!(agent, "Codex");
    }
}
