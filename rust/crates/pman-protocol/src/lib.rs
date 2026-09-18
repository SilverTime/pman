//! Cross-language `pman/2` request and response types.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const PROTOCOL_NAME: &str = "pman";
pub const PROTOCOL_VERSION: u16 = 2;

pub const ERROR_OK: &str = "ok";
pub const ERROR_VAULT_LOCKED: &str = "vault_locked";
pub const ERROR_UNKNOWN_SITE: &str = "unknown_site";
pub const ERROR_SITE_INACTIVE: &str = "site_inactive";
pub const ERROR_HARNESS_INVALID: &str = "harness_invalid";
pub const ERROR_POLICY_DENIED: &str = "policy_denied";
pub const ERROR_RATE_LIMITED: &str = "rate_limited";
pub const ERROR_PENDING_APPROVAL: &str = "pending_approval";
pub const ERROR_RESPONSE_BLOCKED: &str = "response_blocked";
pub const ERROR_REQUEST_FAILED: &str = "request_failed";
pub const ERROR_INVALID_REQUEST: &str = "invalid_request";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("request body must be a JSON object")]
    NotObject,
    #[error("site must be 1-128 non-whitespace characters")]
    InvalidSite,
    #[error("method must be GET/POST/PUT/DELETE/PATCH")]
    InvalidMethod,
    #[error("path must be at most 4096 characters")]
    InvalidPath,
    #[error("path must not contain control characters")]
    ControlCharacter,
    #[error("query, json_body and form must be JSON objects or null")]
    InvalidFieldType,
    #[error("json_body and form cannot be used together")]
    AmbiguousBody,
    #[error("capability must be 1-128 characters using letters, numbers, '.', '_', ':' or '-'")]
    InvalidCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpRequest {
    pub site: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(default)]
    pub query: Option<Value>,
    #[serde(default)]
    pub json_body: Option<Value>,
    #[serde(default)]
    pub form: Option<Value>,
}

impl HttpRequest {
    pub fn validate(mut self) -> Result<Self, ProtocolError> {
        self.site = decode_alias_ref(self.site.trim())?;
        let site = self.site.trim();
        if site.is_empty() || site.chars().count() > 128 {
            return Err(ProtocolError::InvalidSite);
        }
        self.site = site.to_owned();

        self.method = self.method.to_ascii_uppercase();
        if !matches!(
            self.method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH"
        ) {
            return Err(ProtocolError::InvalidMethod);
        }

        if self.path.chars().count() > 4096 {
            return Err(ProtocolError::InvalidPath);
        }
        if self.path.chars().any(char::is_control) {
            return Err(ProtocolError::ControlCharacter);
        }
        if !self.path.is_empty() && !self.path.starts_with('/') {
            self.path.insert(0, '/');
        }
        validate_policy_path(&self.path)?;

        if let Some(capability) = self.capability.as_mut() {
            *capability = capability.trim().to_owned();
            let valid = !capability.is_empty()
                && capability.len() <= 128
                && capability.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric()
                        || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
                });
            if !valid {
                return Err(ProtocolError::InvalidCapability);
            }
        }

        for value in [&self.query, &self.json_body, &self.form] {
            if let Some(value) = value {
                if !value.is_object() {
                    return Err(ProtocolError::InvalidFieldType);
                }
            }
        }
        if self.json_body.is_some() && self.form.is_some() {
            return Err(ProtocolError::AmbiguousBody);
        }
        Ok(self)
    }
}

pub fn encode_alias_ref(alias: &str) -> String {
    format!(
        "pman-alias-utf8:{}",
        URL_SAFE_NO_PAD.encode(alias.as_bytes())
    )
}
/// Policy and transport must authorize the same path, with query carried separately.
pub fn validate_policy_path(path: &str) -> Result<(), ProtocolError> {
    if path.starts_with("//")
        || path.contains(['\\', '?', '#'])
        || path.split('/').any(|s| s == "." || s == "..")
    {
        return Err(ProtocolError::InvalidPath);
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ProtocolError::InvalidPath);
            }
            let digit = |v: u8| match v {
                b'0'..=b'9' => Some(v - b'0'),
                b'a'..=b'f' => Some(v - b'a' + 10),
                b'A'..=b'F' => Some(v - b'A' + 10),
                _ => None,
            };
            let (Some(a), Some(b)) = (digit(bytes[index + 1]), digit(bytes[index + 2])) else {
                return Err(ProtocolError::InvalidPath);
            };
            let decoded = (a << 4) | b;
            if decoded < 32
                || decoded == 127
                || matches!(decoded, b'.' | b'/' | b'\\' | b'%' | b'?' | b'#')
            {
                return Err(ProtocolError::InvalidPath);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}
pub fn decode_alias_ref(alias: &str) -> Result<String, ProtocolError> {
    let Some(encoded) = alias.strip_prefix("pman-alias-utf8:") else {
        return Ok(alias.into());
    };
    if encoded.is_empty() || encoded.len() > 700 {
        return Err(ProtocolError::InvalidSite);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .map_err(|_| ProtocolError::InvalidSite)?;
    let value = String::from_utf8(bytes).map_err(|_| ProtocolError::InvalidSite)?;
    if value.is_empty() || value.chars().count() > 128 {
        return Err(ProtocolError::InvalidSite);
    }
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResultEnvelope {
    pub protocol: String,
    pub protocol_version: u16,
    pub ok: bool,
    pub error_code: String,
}

impl ResultEnvelope {
    pub fn ok() -> Self {
        Self {
            protocol: PROTOCOL_NAME.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            ok: true,
            error_code: ERROR_OK.to_owned(),
        }
    }

    pub fn error(error_code: &str) -> Self {
        Self {
            protocol: PROTOCOL_NAME.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            ok: false,
            error_code: error_code.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> HttpRequest {
        HttpRequest {
            site: " gitlab ".to_owned(),
            method: "get".to_owned(),
            path: "api/v4/projects".to_owned(),
            capability: None,
            query: Some(json!({"owned": "true"})),
            json_body: None,
            form: None,
        }
    }

    #[test]
    fn normalizes_valid_request() {
        let req = request().validate().expect("valid request");
        assert_eq!(req.site, "gitlab");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/v4/projects");
    }

    #[test]
    fn rejects_ambiguous_body() {
        let mut req = request();
        req.json_body = Some(json!({"x": 1}));
        req.form = Some(json!({"x": "1"}));
        assert_eq!(req.validate(), Err(ProtocolError::AmbiguousBody));
    }

    #[test]
    fn result_is_wire_compatible() {
        let result = serde_json::to_value(ResultEnvelope::error(ERROR_POLICY_DENIED))
            .expect("serialize result");
        assert_eq!(result["protocol"], "pman");
        assert_eq!(result["protocol_version"], 2);
        assert_eq!(result["error_code"], "policy_denied");
    }

    #[test]
    fn legacy_alias_reference_is_decoded_before_length_validation() {
        let mut value = request();
        value.site = encode_alias_ref(&"中文站点".repeat(20));
        assert_eq!(value.validate().unwrap().site, "中文站点".repeat(20));
        assert!(decode_alias_ref("pman-alias-utf8:!").is_err());
    }
    #[test]
    fn ambiguous_paths_cannot_bypass_policy() {
        for path in [
            "/api/../admin",
            "/api/%2e%2e/admin",
            "/api/%252e/admin",
            "/api%2fadmin",
            "/api\\admin",
            "//elsewhere",
            "/api?admin=1",
            "/api#x",
            "/api/%0d",
            "/api/%x",
        ] {
            assert!(validate_policy_path(path).is_err(), "{path}");
        }
        assert!(validate_policy_path("/api/%E4%B8%AD%E6%96%87").is_ok());
    }
}
