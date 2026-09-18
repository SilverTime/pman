//! Client for the local Python `pmd` HTTP boundary.
//!
//! The daemon token is accepted only in memory and only sent to loopback
//! addresses. This keeps the desktop IPC adapter from accidentally becoming a
//! credential forwarding proxy for arbitrary URLs.

use crate::HttpRequest;
use reqwest::blocking::Client;
use reqwest::Method;
use serde_json::Value;
use std::{io::Read, time::Duration};
use thiserror::Error;
use url::Url;

const USER_AGENT: &str = "pman/0.3";
const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("daemon 地址必须是本机 HTTP 地址")]
    InvalidAddress,
    #[error("daemon token 不能为空")]
    MissingToken,
    #[error("daemon 请求失败")]
    Request(#[source] reqwest::Error),
    #[error("daemon 返回无效 JSON")]
    Json(#[from] serde_json::Error),
    #[error("daemon 返回的 pman 协议不兼容")]
    Protocol,
    #[error("daemon 返回 HTTP {status}: {message}")]
    Remote { status: u16, message: String },
    #[error("daemon 响应过大")]
    ResponseTooLarge,
}

#[derive(Debug, Clone)]
pub struct DaemonClient {
    base_url: String,
    token: Option<String>,
    client: Client,
}

impl DaemonClient {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Result<Self, DaemonError> {
        let base_url = normalize_base_url(&base_url.into())?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(DaemonError::Request)?;
        Ok(Self {
            base_url,
            token,
            client,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn status(&self) -> Result<Value, DaemonError> {
        self.send(Method::GET, "/v1/status", None, false)
    }

    pub fn sites(&self) -> Result<Value, DaemonError> {
        self.send(Method::GET, "/v1/sites", None, true)
    }

    pub fn http(&self, request: &HttpRequest) -> Result<Value, DaemonError> {
        let request = request
            .clone()
            .validate()
            .map_err(|_| DaemonError::Protocol)?;
        let payload = serde_json::to_value(request)?;
        self.send(Method::POST, "/v1/http", Some(payload), true)
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        payload: Option<Value>,
        authenticated: bool,
    ) -> Result<Value, DaemonError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .client
            .request(method, url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json");
        if authenticated {
            let token = self
                .token
                .as_deref()
                .filter(|token| !token.trim().is_empty())
                .ok_or(DaemonError::MissingToken)?;
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(payload) = payload {
            request = request.json(&payload);
        }
        let mut response = request.send().map_err(DaemonError::Request)?;
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| DaemonError::ResponseTooLarge)?;
        if bytes.len() > MAX_BODY {
            return Err(DaemonError::ResponseTooLarge);
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        validate_protocol(&value)?;
        if !status.is_success() {
            // Do not forward daemon error text: an older daemon may include
            // library/URL details. Keep only a stable, non-sensitive summary.
            let message = match status.as_u16() {
                400 => "daemon 请求无效",
                401 => "daemon token 无效或已吊销",
                403 => "daemon 拒绝请求",
                _ => "daemon 请求失败",
            }
            .to_owned();
            return Err(DaemonError::Remote {
                status: status.as_u16(),
                message,
            });
        }
        Ok(value)
    }
}

fn normalize_base_url(value: &str) -> Result<String, DaemonError> {
    let value = value.trim().trim_end_matches('/');
    let parsed = Url::parse(value).map_err(|_| DaemonError::InvalidAddress)?;
    if parsed.scheme() != "http" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(DaemonError::InvalidAddress);
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return Err(DaemonError::InvalidAddress);
    }
    Ok(value.to_owned())
}

fn validate_protocol(value: &Value) -> Result<(), DaemonError> {
    let protocol = value.get("protocol").and_then(Value::as_str);
    let version = value.get("protocol_version").and_then(Value::as_u64);
    if protocol.is_some()
        && (protocol != Some(pman_protocol::PROTOCOL_NAME)
            || version != Some(pman_protocol::PROTOCOL_VERSION as u64))
    {
        return Err(DaemonError::Protocol);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    fn spawn_response(
        body: &'static str,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read");
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).expect("write");
        });
        (format!("http://{address}"), receiver, handle)
    }

    #[test]
    fn only_loopback_daemon_addresses_are_allowed() {
        assert!(DaemonClient::new("https://127.0.0.1:9777", None).is_err());
        assert!(DaemonClient::new("http://example.test:9777", None).is_err());
        assert!(DaemonClient::new("http://127.0.0.1:9777", None).is_ok());
    }

    #[test]
    fn http_call_validates_protocol_and_sends_bearer_only_to_daemon() {
        let (base, receiver, handle) = spawn_response(
            r#"{"protocol":"pman","protocol_version":2,"ok":true,"error_code":"ok","status_code":200}"#,
        );
        let client = DaemonClient::new(base, Some("pm_test".to_owned())).expect("client");
        let response = client
            .http(&HttpRequest {
                site: "api".to_owned(),
                method: "GET".to_owned(),
                path: "/health".to_owned(),
                capability: None,
                query: None,
                json_body: None,
                form: None,
            })
            .expect("response");
        handle.join().expect("server");
        let request = receiver.recv().expect("request");
        assert_eq!(response["error_code"], "ok");
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer pm_test"));
        assert!(request.contains("/v1/http"));
    }

    #[test]
    fn protocol_mismatch_is_rejected() {
        let (base, _receiver, handle) =
            spawn_response(r#"{"protocol":"pman","protocol_version":9,"ok":true}"#);
        let client = DaemonClient::new(base, None).expect("client");
        assert!(matches!(client.status(), Err(DaemonError::Protocol)));
        handle.join().expect("server");
    }
}
