//! Secret injection and response sanitization for the broker.

use crate::{RedactionPolicy, SiteSummary};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{
    blocking::{Client, RequestBuilder},
    header::{HeaderMap, HeaderName, HeaderValue},
    Method,
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, io::Read, time::Duration};
use thiserror::Error;
use url::form_urlencoded;

pub const USER_AGENT: &str = "pman/0.3";
pub const HARD_RESPONSE_CAP: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid request method or header")]
    InvalidRequest,
    #[error("secret missing required field")]
    MissingSecret,
    #[error("unsupported auth_type")]
    UnsupportedAuthType,
    #[error("request failed")]
    Request(#[from] reqwest::Error),
    #[error("response read failed")]
    Read(#[from] std::io::Error),
    #[error("response contains a credential")]
    ResponseBlocked,
    #[error("GitLab CSRF bootstrap failed; refresh the connection login")]
    GitlabCsrf,
}

#[derive(Debug)]
pub struct RawResponse {
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub original_bytes: usize,
    pub hard_truncated: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CleanResponse {
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body_json: Option<Value>,
    pub body_text: Option<String>,
    pub redactions: usize,
    pub truncated: bool,
    pub truncated_original_bytes: usize,
}

pub fn execute(
    site: &SiteSummary,
    secret: &Value,
    method: &str,
    path: &str,
    query: Option<&Value>,
    json_body: Option<&Value>,
    form: Option<&Value>,
    timeout: Duration,
) -> Result<RawResponse, ProxyError> {
    let url = build_url(&site.site_url, path, query)?;
    let target = url::Url::parse(&url).map_err(|_| ProxyError::InvalidRequest)?;
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| ProxyError::InvalidRequest)?;
    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(site.insecure_tls)
        // Never follow redirects with a credential-bearing request. Returning
        // the 3xx response is safer than accidentally leaking auth headers.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let csrf = gitlab_csrf(&client, site, secret, &method, &target)?;
    let mut request = client
        .request(method, url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json, text/plain, */*");
    request = inject_auth(request, &site.auth_type, secret, &target)?;
    if let Some(token) = csrf.as_ref() {
        let mut value = HeaderValue::from_str(token).map_err(|_| ProxyError::GitlabCsrf)?;
        value.set_sensitive(true);
        request = request.header("X-CSRF-Token", value);
    }
    if let Some(body) = json_body {
        request = request.json(body);
    } else if let Some(body) = form {
        request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encode_form(body)?);
    }
    let mut response = request.send()?;
    let status_code = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let mut body = Vec::new();
    response
        .by_ref()
        .take((HARD_RESPONSE_CAP + 1) as u64)
        .read_to_end(&mut body)?;
    let original_bytes = body.len();
    let hard_truncated = original_bytes > HARD_RESPONSE_CAP;
    if hard_truncated {
        body.truncate(HARD_RESPONSE_CAP);
    }
    // A token obtained during this request is not in the vault's redaction set.
    // Fail closed if the server echoes it, even under an innocuous key/header.
    if let Some(token) = csrf.as_ref() {
        if body.windows(token.len()).any(|part| part == token.as_bytes())
            || headers.iter().any(|(key, value)| {
                key.contains(token.as_str()) || value.contains(token.as_str())
            })
        {
            return Err(ProxyError::ResponseBlocked);
        }
    }
    Ok(RawResponse {
        status_code,
        headers,
        body,
        original_bytes,
        hard_truncated,
    })
}

// Authentication bootstrap only: fixed same-origin page, no redirects, no
// persistence, no retry of the caller's mutation, and no HTML returned to AI.
fn gitlab_csrf(
    client: &Client,
    site: &SiteSummary,
    secret: &Value,
    method: &Method,
    target: &url::Url,
) -> Result<Option<zeroize::Zeroizing<String>>, ProxyError> {
    if !matches!(site.auth_type.as_str(), "login" | "cookie_jar")
        || !matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE)
    {
        return Ok(None);
    }
    let Some((prefix, _)) = target.path().split_once("/api/v4/") else {
        return Ok(None);
    };
    let cookies = cookie_pairs(secret, target)?;
    let Some((_, session)) = cookies.iter().find(|(name, _)| name == "_gitlab_session") else {
        return Ok(None);
    };
    let mut bootstrap = target.clone();
    bootstrap.set_path(&format!("{prefix}/-/profile"));
    bootstrap.set_query(None);
    bootstrap.set_fragment(None);
    // A path-scoped API cookie must not be widened to the bootstrap page.
    if !cookie_pairs(secret, &bootstrap)?.iter().any(|(name, value)| {
        name == "_gitlab_session" && value == session
    }) {
        return Err(ProxyError::GitlabCsrf);
    }
    let request = client.get(bootstrap.clone())
        .header("User-Agent", USER_AGENT)
        .header("Accept", "text/html");
    let mut response = inject_auth(request, &site.auth_type, secret, &bootstrap)?
        .send().map_err(|_| ProxyError::GitlabCsrf)?;
    if response.status() != reqwest::StatusCode::OK
        || !response.headers().get("content-type").and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/html"))
    {
        return Err(ProxyError::GitlabCsrf);
    }
    let mut html = zeroize::Zeroizing::new(Vec::new());
    response.by_ref().take((HARD_RESPONSE_CAP + 1) as u64).read_to_end(&mut html)
        .map_err(|_| ProxyError::GitlabCsrf)?;
    if html.len() > HARD_RESPONSE_CAP {
        return Err(ProxyError::GitlabCsrf);
    }
    let html = std::str::from_utf8(&html).map_err(|_| ProxyError::GitlabCsrf)?;
    csrf_from_html(html).map(Some)
}

fn csrf_from_html(html: &str) -> Result<zeroize::Zeroizing<String>, ProxyError> {
    // Rails emits a base64 masked token in a quoted meta attribute. Restrict
    // the accepted alphabet/size rather than treating arbitrary HTML as a header.
    let tags = regex::Regex::new(r"(?is)<meta\s+[^>]*>").expect("static meta regex");
    let attrs = regex::Regex::new(r#"(?i)([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')"#)
        .expect("static attribute regex");
    let mut token = None;
    for tag in tags.find_iter(html) {
        let mut name = None;
        let mut content = None;
        for attr in attrs.captures_iter(tag.as_str()) {
            let value = attr.get(2).or_else(|| attr.get(3)).unwrap().as_str();
            match attr[1].to_ascii_lowercase().as_str() {
                "name" => name = Some(value),
                "content" => content = Some(value),
                _ => {}
            }
        }
        if name != Some("csrf-token") { continue; }
        let value = content.ok_or(ProxyError::GitlabCsrf)?;
        if token.is_some() || !(32..=512).contains(&value.len())
            || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/_=-".contains(&b))
        {
            return Err(ProxyError::GitlabCsrf);
        }
        token = Some(zeroize::Zeroizing::new(value.to_owned()));
    }
    token.ok_or(ProxyError::GitlabCsrf)
}

pub fn sanitize(
    response: RawResponse,
    policy: &RedactionPolicy,
    secret: &Value,
    site: &SiteSummary,
) -> Result<CleanResponse, ProxyError> {
    let secrets = secret_values(secret, site);
    let (headers, header_count) = redact_headers(response.headers, policy, &secrets);
    let max_bytes = policy.max_response_bytes.min(HARD_RESPONSE_CAP);
    let truncated = response.hard_truncated || response.body.len() > max_bytes;
    let payload = &response.body[..response.body.len().min(max_bytes)];
    let text = String::from_utf8_lossy(payload).to_string();
    let (body_json, body_text, body_count) = match serde_json::from_str::<Value>(&text) {
        Ok(value) => {
            let (value, count) = redact_json(value, policy, &secrets);
            (Some(value), None, count)
        }
        Err(_) => {
            let (value, count) = redact_text(text, policy, &secrets);
            (None, Some(value), count)
        }
    };
    let clean = CleanResponse {
        status_code: response.status_code,
        headers,
        body_json,
        body_text,
        redactions: header_count + body_count,
        truncated,
        truncated_original_bytes: if truncated {
            response.original_bytes
        } else {
            0
        },
    };
    if contains_secret(&clean.headers, &secrets)
        || clean
            .body_json
            .as_ref()
            .is_some_and(|body| contains_secret(body, &secrets))
        || clean
            .body_text
            .as_ref()
            .is_some_and(|body| contains_secret(body, &secrets))
    {
        return Err(ProxyError::ResponseBlocked);
    }
    Ok(clean)
}

pub(crate) fn build_url(base: &str, path: &str, query: Option<&Value>) -> Result<String, ProxyError> {
    let mut url = base.trim_end_matches('/').to_owned();
    if !path.is_empty() {
        if !path.starts_with('/') {
            url.push('/');
        }
        url.push_str(path);
    }
    if let Some(Value::Object(query)) = query {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in query {
            match value {
                Value::Array(items) => {
                    for item in items {
                        serializer.append_pair(key, &value_to_string(item));
                    }
                }
                _ => {
                    serializer.append_pair(key, &value_to_string(value));
                }
            }
        }
        let encoded = serializer.finish();
        if !encoded.is_empty() {
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&encoded);
        }
    }
    let parsed = url::Url::parse(&url).map_err(|_| ProxyError::InvalidRequest)?;
    let base = url::Url::parse(base).map_err(|_| ProxyError::InvalidRequest)?;
    let authority_and_path = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or(ProxyError::InvalidRequest)?;
    let raw_path = authority_and_path
        .find('/')
        .map(|index| &authority_and_path[index..])
        .unwrap_or("/")
        .split(['?', '#'])
        .next()
        .unwrap_or("/");
    // The transport may not silently normalize a path after policy approval.
    // In particular URL parsers collapse encoded dot segments and backslashes.
    if parsed.origin() != base.origin() || parsed.fragment().is_some() || parsed.path() != raw_path
    {
        return Err(ProxyError::InvalidRequest);
    }
    Ok(url)
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn inject_auth(
    mut request: RequestBuilder,
    auth_type: &str,
    secret: &Value,
    target: &url::Url,
) -> Result<RequestBuilder, ProxyError> {
    let object = secret.as_object().ok_or(ProxyError::MissingSecret)?;
    match auth_type {
        "api_token" => {
            let token = object
                .get("token")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(ProxyError::MissingSecret)?;
            let header = object
                .get("header")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("Authorization");
            let mut value = token.to_owned();
            if header.eq_ignore_ascii_case("authorization") && !starts_with_auth_scheme(&value) {
                value = format!("Bearer {value}");
            }
            let name = HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| ProxyError::InvalidRequest)?;
            let value = HeaderValue::from_str(&value).map_err(|_| ProxyError::InvalidRequest)?;
            request = request.header(name, value);
        }
        "http_basic" => {
            let username = object.get("username").and_then(Value::as_str).unwrap_or("");
            let password = object.get("password").and_then(Value::as_str).unwrap_or("");
            request = request.header(
                "Authorization",
                format!("Basic {}", BASE64.encode(format!("{username}:{password}"))),
            );
        }
        "cookie_jar" | "login" if crate::e10::looks_like_session(secret, target) => {
            let (sid, cookie, agent) =
                crate::e10::request_auth(secret, target).map_err(|_| ProxyError::MissingSecret)?;
            request = request
                .header("eteamsid", sid)
                .header("Cookie", cookie)
                .header("agentType", &agent)
                .header("isAgent", "true")
                .header("User-Agent", format!("AgentType={agent},IsAgent=true"));
        }
        "cookie_jar" | "login" if secret.get("auth_profile").is_some() => {},
        "cookie_jar" | "login" => {
            let pairs = cookie_pairs(secret, target)?
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>();
            if pairs.is_empty() {
                return Err(ProxyError::MissingSecret);
            }
            request = request.header("Cookie", pairs.join("; "));
        }
        "e10" => {
            let (sid, cookie, agent) =
                crate::e10::request_auth(secret, target).map_err(|_| ProxyError::MissingSecret)?;
            request = request
                .header("eteamsid", sid)
                .header("Cookie", cookie)
                .header("agentType", &agent)
                .header("isAgent", "true")
                .header("User-Agent", format!("AgentType={agent},IsAgent=true"));
        }
        "authflow" => {}
        _ => return Err(ProxyError::UnsupportedAuthType),
    }
    if (secret.get("auth_profile").is_some() || auth_type == "authflow")
        && !crate::e10::looks_like_session(secret, target)
    {
        request = crate::authflow::apply_auth(request, secret, target).map_err(|_| ProxyError::MissingSecret)?;
    }
    Ok(request)
}

/// Cookie records captured from a browser retain their security scope. Legacy
/// maps are scoped by the fixed site's origin and remain readable on migration.
pub(crate) fn cookie_pairs(
    secret: &Value,
    target: &url::Url,
) -> Result<Vec<(String, String)>, ProxyError> {
    let cookies = secret.get("cookies").ok_or(ProxyError::MissingSecret)?;
    let host = target
        .host_str()
        .ok_or(ProxyError::InvalidRequest)?
        .to_ascii_lowercase();
    let now = chrono::Utc::now().timestamp() as f64;
    let mut pairs = Vec::new();
    let mut push = |name: &str, value: String| -> Result<(), ProxyError> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value
                .bytes()
                .any(|byte| byte < 0x21 || byte > 0x7e || b"\";,\\".contains(&byte))
        {
            return Err(ProxyError::InvalidRequest);
        }
        pairs.push((name.to_owned(), value));
        Ok(())
    };
    match cookies {
        Value::Object(cookies) => {
            for (name, value) in cookies {
                push(name, value_to_string(value))?;
            }
        }
        Value::Array(cookies) => {
            for cookie in cookies {
                let name = cookie
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(ProxyError::MissingSecret)?;
                let value = cookie
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or(ProxyError::MissingSecret)?;
                let domain = cookie
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or(&host)
                    .trim_start_matches('.')
                    .to_ascii_lowercase();
                let host_only = cookie
                    .get("host_only")
                    .and_then(Value::as_bool)
                    .unwrap_or_else(|| {
                        !cookie
                            .get("domain")
                            .and_then(Value::as_str)
                            .is_some_and(|value| value.starts_with('.'))
                    });
                if host != domain && (host_only || !host.ends_with(&format!(".{domain}"))) {
                    continue;
                }
                if cookie
                    .get("secure")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    && target.scheme() != "https"
                {
                    continue;
                }
                let expiry = cookie.get("expires").or_else(|| cookie.get("expires_at"));
                let expires = expiry.and_then(Value::as_f64).or_else(|| {
                    expiry
                        .and_then(Value::as_str)
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .map(|value| value.timestamp() as f64)
                });
                // Browser session cookies have no expiry; WebView2 can report -1.
                if expires.is_some_and(|expires| expires >= 0.0 && expires <= now) {
                    continue;
                }
                let path = cookie.get("path").and_then(Value::as_str).unwrap_or("/");
                let request_path = target.path();
                if request_path != path
                    && !(request_path.starts_with(path)
                        && (path.ends_with('/')
                            || request_path.as_bytes().get(path.len()) == Some(&b'/')))
                {
                    continue;
                }
                push(name, value.to_owned())?;
            }
        }
        _ => return Err(ProxyError::MissingSecret),
    }
    Ok(pairs)
}

fn encode_form(value: &Value) -> Result<String, ProxyError> {
    let object = value.as_object().ok_or(ProxyError::InvalidRequest)?;
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in object {
        serializer.append_pair(key, &value_to_string(value));
    }
    Ok(serializer.finish())
}

fn collect_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.to_string(), value.to_owned()))
        })
        .collect()
}

fn redact_headers(
    headers: BTreeMap<String, String>,
    policy: &RedactionPolicy,
    secrets: &[String],
) -> (BTreeMap<String, String>, usize) {
    let mut output = BTreeMap::new();
    let mut count = 0;
    for (key, value) in headers {
        if matches_pattern(&key, &policy.strip_headers) {
            count += 1;
            continue;
        }
        let (value, replaced) = replace_secrets(value, secrets);
        count += replaced;
        output.insert(key, value);
    }
    (output, count)
}

fn redact_json(value: Value, policy: &RedactionPolicy, secrets: &[String]) -> (Value, usize) {
    match value {
        Value::Object(object) => {
            let mut output = Map::new();
            let mut count = 0;
            for (key, value) in object {
                if matches_pattern(&key, &policy.json_keys) {
                    output.insert(key, Value::String(crate::REDACTED.to_owned()));
                    count += 1;
                    continue;
                }
                let (safe_key, key_count) = replace_secrets(key, secrets);
                let (safe_value, value_count) = redact_json(value, policy, secrets);
                output.insert(safe_key, safe_value);
                count += key_count + value_count;
            }
            (Value::Object(output), count)
        }
        Value::Array(items) => {
            let mut count = 0;
            let items = items
                .into_iter()
                .map(|item| {
                    let (item, item_count) = redact_json(item, policy, secrets);
                    count += item_count;
                    item
                })
                .collect();
            (Value::Array(items), count)
        }
        Value::String(value) => {
            let (value, count) = replace_secrets(value, secrets);
            (Value::String(value), count)
        }
        value => (value, 0),
    }
}

fn redact_text(mut text: String, policy: &RedactionPolicy, secrets: &[String]) -> (String, usize) {
    let mut count = 0;
    // Parse the text shape once; user-supplied key patterns are only used for
    // matching the captured key, never interpolated into a regex.
    let token = regex::Regex::new(
        r#"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)"#,
    )
    .expect("static redaction regex");
    text = token
        .replace_all(&text, |caps: &regex::Captures<'_>| {
            let key = caps
                .name("key")
                .map(|value| value.as_str())
                .unwrap_or_default();
            if !matches_pattern(key, &policy.json_keys) {
                return caps
                    .get(0)
                    .map(|value| value.as_str())
                    .unwrap_or_default()
                    .to_owned();
            }
            count += 1;
            format!("{}={}", key, crate::REDACTED)
        })
        .to_string();
    let (text, replaced) = replace_secrets(text, secrets);
    (text, count + replaced)
}

fn matches_pattern(value: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return false;
        }
        let plain = pattern.trim_start_matches("(?i)");
        let has_regex_syntax = plain.contains('*')
            || plain.contains('.')
            || plain.contains('[')
            || plain.contains('(')
            || plain.contains('?')
            || plain.contains('|')
            || plain.contains('^')
            || plain.contains('$');
        if !has_regex_syntax {
            return value.eq_ignore_ascii_case(plain)
                || value
                    .to_ascii_lowercase()
                    .contains(&plain.to_ascii_lowercase());
        }
        regex::RegexBuilder::new(plain)
            .case_insensitive(true)
            .build()
            .map(|regex| regex.is_match(value))
            .unwrap_or(false)
    })
}

fn replace_secrets(mut text: String, secrets: &[String]) -> (String, usize) {
    let mut count = 0;
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if secret.len() < 8 {
            let mut start = 0;
            while start < text.len() {
                let Some(relative) = text[start..].find(secret) else {
                    break;
                };
                let index = start + relative;
                let before = text[..index].chars().next_back();
                let after = text[index + secret.len()..].chars().next();
                let boundary = |value: Option<char>| {
                    value.is_none_or(|value| !(value.is_ascii_alphanumeric() || value == '_'))
                };
                if boundary(before) && boundary(after) {
                    text.replace_range(index..index + secret.len(), crate::REDACTED);
                    count += 1;
                    start = index + crate::REDACTED.len();
                } else {
                    start = index + secret.len();
                }
            }
        } else {
            let occurrences = text.matches(secret).count();
            if occurrences > 0 {
                text = text.replace(secret, crate::REDACTED);
                count += occurrences;
            }
        }
    }
    (text, count)
}

pub(crate) fn secret_values(secret: &Value, site: &SiteSummary) -> Vec<String> {
    let mut values = Vec::new();
    if matches!(site.auth_type.as_str(), "cookie_jar" | "login" | "authflow" | "e10") {
        collect_cookie_values(secret, &mut values);
        if let Some(sid) = secret.get("eteamsid").and_then(Value::as_str) {
            values.push(sid.to_owned());
        }
        if let Some(variables) = secret.get("variables") { collect_strings(variables, &mut values); }
        if let Some(profile) = secret.get("auth_profile") {
            // Constants may themselves be credentials; redact them too.
            if let Some(headers) = profile.get("headers") { collect_strings(headers, &mut values); }
            if let Some(cookies) = profile.get("cookies") { collect_strings(cookies, &mut values); }
        }
    } else {
        collect_strings(secret, &mut values);
    }
    if site.auth_type == "api_token" {
        if let Some(token) = secret.get("token").and_then(Value::as_str) {
            if !starts_with_auth_scheme(token) {
                values.push(format!("Bearer {token}"));
            }
        }
    } else if site.auth_type == "http_basic" {
        let username = secret.get("username").and_then(Value::as_str).unwrap_or("");
        let password = secret.get("password").and_then(Value::as_str).unwrap_or("");
        let encoded = BASE64.encode(format!("{username}:{password}"));
        values.push(encoded.clone());
        values.push(format!("Basic {encoded}"));
    }
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    values.dedup();
    values
}

fn collect_cookie_values(secret: &Value, output: &mut Vec<String>) {
    let Some(cookies) = secret.get("cookies") else {
        return;
    };
    match cookies {
        Value::Object(cookies) => {
            for value in cookies.values() {
                let value = value_to_string(value);
                if !value.is_empty() {
                    output.push(value.clone());
                }
            }
        }
        Value::Array(cookies) => {
            for cookie in cookies {
                let Some(cookie) = cookie.as_object() else {
                    continue;
                };
                let Some(value) = cookie
                    .get("value")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                output.push(value.to_owned());
            }
        }
        _ => {}
    }
}

fn collect_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(value) if !value.is_empty() => output.push(value.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect_strings(item, output)),
        Value::Object(items) => items
            .values()
            .for_each(|item| collect_strings(item, output)),
        _ => {}
    }
}

fn starts_with_auth_scheme(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    ["bearer ", "basic ", "token ", "private-token "]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn contains_secret<T: serde::Serialize>(value: &T, secrets: &[String]) -> bool {
    let Ok(text) = serde_json::to_string(value) else {
        return false;
    };
    secrets
        .iter()
        .any(|secret| secret.len() >= 8 && text.contains(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Policy;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    const TEST_CSRF: &str = "syntheticCsrfToken012345678901234567890123456789012345678901234567890=";

    // Local HTTP fixture only; no real vault or credentials are used.
    fn csrf_server(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "missing request");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0u8; 4096];
                    let size = stream.read(&mut buffer).unwrap();
                    assert!(size > 0);
                    bytes.extend_from_slice(&buffer[..size]);
                    if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length: usize = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        }).unwrap_or(0);
                        if bytes.len() >= end + 4 + length { break; }
                    }
                }
                requests.push(String::from_utf8(bytes).unwrap());
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        (format!("http://{address}"), handle)
    }

    fn html_response(body: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    }

    #[test]
    fn gitlab_csrf_parser_accepts_rails_and_rejects_missing_invalid_duplicate() {
        for html in [
            format!(r#"<meta name="csrf-token" content="{TEST_CSRF}" />"#),
            format!("<META content='{TEST_CSRF}' name='csrf-token'>"),
        ] {
            assert_eq!(csrf_from_html(&html).unwrap().as_str(), TEST_CSRF);
        }
        for html in [String::new(), "<meta name='csrf-token' content='bad\r\nheader'>".into(),
            format!("<meta name='csrf-token' content='{TEST_CSRF}'><meta name='csrf-token' content='{TEST_CSRF}'>")]
        {
            assert!(csrf_from_html(&html).is_err());
        }
    }

    #[test]
    fn gitlab_writes_bootstrap_same_origin_preserve_json_and_do_not_retry() {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let (url, server) = csrf_server(vec![
                html_response(&format!("<meta name='csrf-token' content='{TEST_CSRF}'>")),
                "HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            ]);
            let mut site = site("login");
            site.site_url = url;
            let secret = json!({"cookies":{"_gitlab_session":"synthetic-session"}});
            let raw = execute(&site, &secret, method, "/gitlab/api/v4/projects/523/repository/commits",
                Some(&json!({"q":"value"})), Some(&json!({"branch":"test"})), None, Duration::from_secs(5)).unwrap();
            assert_eq!(raw.status_code, 409);
            let requests = server.join().unwrap();
            assert!(requests[0].starts_with("GET /gitlab/-/profile HTTP/1.1"));
            assert!(!requests[0].to_ascii_lowercase().contains("x-csrf-token"));
            assert!(requests[1].starts_with(&format!("{method} /gitlab/api/v4/projects/523/repository/commits?q=value ")));
            assert!(requests[1].contains(&format!("x-csrf-token: {TEST_CSRF}")));
            assert!(requests.iter().all(|r| r.contains("_gitlab_session=synthetic-session")));
            assert!(requests[1].ends_with(r#"{"branch":"test"}"#));
        }
    }

    #[test]
    fn gitlab_csrf_missing_or_redirect_stops_before_mutation() {
        for response in [html_response("<html>login required</html>"),
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\n\r\n".into()] {
            let (url, server) = csrf_server(vec![response]);
            let mut site = site("login");
            site.site_url = url;
            assert!(matches!(execute(&site, &json!({"cookies":{"_gitlab_session":"synthetic-session"}}),
                "POST", "/api/v4/projects", None, None, None, Duration::from_secs(5)), Err(ProxyError::GitlabCsrf)));
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn gitlab_csrf_does_not_widen_cookie_scope() {
        let site = site("login");
        let secret = json!({"cookies":[{"name":"_gitlab_session","value":"synthetic-session",
            "path":"/api","domain":"example.test"}]});
        assert!(matches!(execute(&site, &secret, "POST", "/api/v4/projects", None, None, None, Duration::from_secs(5)),
            Err(ProxyError::GitlabCsrf)));
    }

    #[test]
    fn gitlab_csrf_echo_is_blocked_in_body_and_headers() {
        for response in [html_response(TEST_CSRF),
            format!("HTTP/1.1 200 OK\r\nX-Trace: {TEST_CSRF}\r\nContent-Length: 0\r\n\r\n")] {
            let (url, server) = csrf_server(vec![
                html_response(&format!("<meta name='csrf-token' content='{TEST_CSRF}'>")), response]);
            let mut site = site("cookie_jar");
            site.site_url = url;
            assert!(matches!(execute(&site, &json!({"cookies":{"_gitlab_session":"synthetic-session"}}),
                "POST", "/api/v4/projects", None, None, None, Duration::from_secs(5)), Err(ProxyError::ResponseBlocked)));
            assert_eq!(server.join().unwrap().len(), 2);
        }
    }

    #[test]
    fn gitlab_get_and_other_auth_paths_do_not_bootstrap() {
        for (auth, secret, method, path) in [
            ("login", json!({"cookies":{"_gitlab_session":"synthetic-session"}}), "GET", "/api/v4/projects"),
            ("login", json!({"cookies":{"sid":"synthetic-session"}}), "POST", "/api/v4/projects"),
            ("login", json!({"cookies":{"_gitlab_session":"synthetic-session"}}), "POST", "/other"),
            ("api_token", json!({"token":"synthetic-token"}), "POST", "/api/v4/projects"),
        ] {
            let (url, server) = csrf_server(vec!["HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".into()]);
            let mut site = site(auth);
            site.site_url = url;
            assert_eq!(execute(&site, &secret, method, path, None, None, None, Duration::from_secs(5)).unwrap().status_code, 204);
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 1);
            assert!(!requests[0].to_ascii_lowercase().contains("x-csrf-token"));
        }
    }

    fn site(auth_type: &str) -> SiteSummary {
        SiteSummary {
            id: "id".to_owned(),
            alias: "api".to_owned(),
            name: None,
            site_url: "https://example.test".to_owned(),
            auth_type: auth_type.to_owned(),
            purpose: None,
            tags: vec![],
            login_script: None,
            refresh_on: vec![],
            requires_human: false,
            insecure_tls: false,
            created_at: String::new(),
            updated_at: String::new(),
            last_used_at: None,
            expires_at: None,
            status: "active".to_owned(),
        }
    }

    #[test]
    fn response_json_is_redacted_and_known_secret_is_not_returned() {
        let site = site("api_token");
        let raw = RawResponse {
            status_code: 200,
            headers: [("X-Auth-Token".to_owned(), "secret-token".to_owned()), ("X-Trace".to_owned(), "ok".to_owned())].into_iter().collect(),
            body: serde_json::to_vec(&json!({"access_token":"server-token","data":"secret-token","nested":{"password":"pw"}})).unwrap(),
            original_bytes: 100,
            hard_truncated: false,
        };
        let policy = Policy::default().redact;
        let clean =
            sanitize(raw, &policy, &json!({"token":"secret-token"}), &site).expect("sanitize");
        assert!(!serde_json::to_string(&clean)
            .unwrap()
            .contains("secret-token"));
        assert_eq!(
            clean.body_json.as_ref().unwrap()["access_token"],
            crate::REDACTED
        );
        assert_eq!(clean.body_json.as_ref().unwrap()["data"], crate::REDACTED);
        assert!(!clean.headers.contains_key("x-auth-token"));
    }

    #[test]
    fn python_style_regex_redaction_patterns_are_supported() {
        let site = site("api_token");
        let raw = RawResponse {
            status_code: 200,
            headers: BTreeMap::new(),
            body: serde_json::to_vec(
                &json!({"access_token":"server-value","api_key":"server-key"}),
            )
            .unwrap(),
            original_bytes: 40,
            hard_truncated: false,
        };
        let mut policy = Policy::default().redact;
        policy.json_keys = vec!["(?i).*token.*".to_owned(), "api[_-]?key".to_owned()];
        let clean =
            sanitize(raw, &policy, &json!({"token":"secret-token"}), &site).expect("sanitize");
        assert_eq!(
            clean.body_json.as_ref().unwrap()["access_token"],
            crate::REDACTED
        );
        assert_eq!(
            clean.body_json.as_ref().unwrap()["api_key"],
            crate::REDACTED
        );
    }

    #[test]
    fn login_cookie_values_are_redacted_without_masking_cookie_names() {
        let site = site("login");
        let raw = RawResponse {
            status_code: 200,
            headers: [("X-Request".to_owned(), "sid=webview-session".to_owned())]
                .into_iter()
                .collect(),
            body: serde_json::to_vec(&json!({"data":"sid=webview-session"})).unwrap(),
            original_bytes: 40,
            hard_truncated: false,
        };
        let clean = sanitize(
            raw,
            &Policy::default().redact,
            &json!({"cookies":[{"name":"sid","value":"webview-session"}]}),
            &site,
        )
        .expect("sanitize");
        assert_eq!(clean.headers["X-Request"], "sid=***REDACTED***");
        assert_eq!(
            clean.body_json.as_ref().unwrap()["data"],
            "sid=***REDACTED***"
        );
    }

    #[test]
    fn authflow_response_redacts_sessions_without_masking_metadata() {
        let site = site("authflow");
        let raw = RawResponse {
            status_code: 200, headers: BTreeMap::new(),
            body: serde_json::to_vec(&json!({"data":"synthetic-session_value","origin":"https://authflow.example","account":"user-1"})).unwrap(),
            original_bytes: 100, hard_truncated: false,
        };
        let clean = sanitize(raw,&Policy::default().redact,&json!({"session_value":"synthetic-session_value","origin":"https://authflow.example","account_id":"user-1",
            "cookies":[{"name":"SESSION","value":"synthetic-session_value","path":"/","domain":"authflow.example"}]}),&site).unwrap();
        assert_eq!(clean.body_json.as_ref().unwrap()["data"], crate::REDACTED);
        assert_eq!(
            clean.body_json.as_ref().unwrap()["origin"],
            "https://authflow.example"
        );
        assert_eq!(clean.body_json.as_ref().unwrap()["account"], "user-1");
    }

    #[test]
    fn transport_rejects_paths_that_url_parser_would_change_after_approval() {
        for path in [
            "/allowed/../admin",
            "/allowed/%2e%2e/admin",
            "/allowed\\..\\admin",
            "/allowed#admin",
        ] {
            assert!(
                build_url("https://authflow.example", path, None).is_err(),
                "{path}"
            );
        }
        assert_eq!(
            build_url(
                "https://authflow.example",
                "/api/check",
                Some(&json!({"q":"中文"}))
            )
            .unwrap(),
            "https://authflow.example/api/check?q=%E4%B8%AD%E6%96%87"
        );
    }

    #[test]
    fn basic_and_cookie_headers_are_injected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let (sender, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            for _ in 0..3 {
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
                sender
                    .send(String::from_utf8_lossy(&request).to_string())
                    .expect("capture");
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .expect("response");
            }
        });
        let mut basic = site("http_basic");
        basic.site_url = format!("http://{address}");
        let mut cookie = site("cookie_jar");
        cookie.site_url = format!("http://{address}");
        let mut login = site("login");
        login.site_url = format!("http://{address}");
        execute(
            &basic,
            &json!({"username":"u","password":"p"}),
            "GET",
            "/basic",
            None,
            None,
            None,
            Duration::from_secs(5),
        )
        .expect("basic request");
        execute(
            &cookie,
            &json!({"cookies":[{"name":"sid","value":"abc"}]}),
            "GET",
            "/cookie",
            None,
            None,
            None,
            Duration::from_secs(5),
        )
        .expect("cookie request");
        execute(
            &login,
            &json!({"cookies":[{"name":"sid","value":"webview"}]}),
            "GET",
            "/login",
            None,
            None,
            None,
            Duration::from_secs(5),
        )
        .expect("login request");
        thread.join().expect("server");
        let requests = [
            receiver.recv().expect("basic capture"),
            receiver.recv().expect("cookie capture"),
            receiver.recv().expect("login capture"),
        ];
        assert!(requests.iter().any(|request| request
            .to_ascii_lowercase()
            .contains("authorization: basic dtpw")));
        assert!(requests
            .iter()
            .any(|request| request.to_ascii_lowercase().contains("cookie: sid=abc")));
        assert!(requests
            .iter()
            .any(|request| request.to_ascii_lowercase().contains("cookie: sid=webview")));
    }
}
