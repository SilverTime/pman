//! Optional pman/2 loopback compatibility. Shares the native Broker and exposes no administration.
use crate::service::Shared;
use pman_core::ipc::{self, IpcRequest};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use zeroize::Zeroizing;

pub fn start(shared: Shared) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind("127.0.0.1:9777") {
            Ok(l) => l,
            Err(_) => {
                if let Ok(mut m) = shared.management.lock() {
                    m.startup_error = Some("旧协议端口 9777 被占用；原生 MCP 通道仍可使用".into());
                }
                return;
            }
        };
        let active = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming().flatten() {
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 16).then_some(n + 1)
                })
                .is_err()
            {
                drop(stream);
                continue;
            }
            let shared = shared.clone();
            let active = active.clone();
            std::thread::spawn(move || {
                struct Slot(Arc<AtomicUsize>);
                impl Drop for Slot {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _slot = Slot(active);
                handle(stream, shared)
            });
        }
    });
}
fn handle(mut stream: TcpStream, shared: Shared) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let response=read_request(&mut stream).map(|(method,path,token,body)|{
        if method=="GET"&&path=="/v1/status"{return match shared.status(){Ok(status)=>ipc::result_ok(json!({"initialized":status["initialized"],"unlocked":status["service_running"],"service_running":status["service_running"],"service_paused":status["service_paused"],"managed":true})),Err(_)=>ipc::result_error("request_failed","Broker unavailable")}}
        let harness=match shared.core.lock(){Ok(mut core)=>match core.vault.authenticate_legacy_token(&token){Ok(h)=>h,Err(_)=>return ipc::result_error("harness_invalid","Invalid legacy identity")},Err(_)=>return ipc::result_error("request_failed","Broker unavailable")};
        let (operation,args)=match (method.as_str(),path.split('?').next().unwrap_or("")){
            ("GET","/v1/sites")=>("sites",json!({})),
            ("POST","/v1/http")=>("http",body),
            ("GET","/v1/approval")=>{let id=tauri::Url::parse(&format!("http://127.0.0.1{path}")).ok().and_then(|u|u.query_pairs().find(|(k,_)|k=="id").map(|(_,v)|v.into_owned())).unwrap_or_default();("request_status",json!({"req_id":id}))},
            _=>return ipc::result_error("policy_denied","Administrative operations are desktop-only"),
        };
        shared.dispatch_authenticated(&IpcRequest{client_id:"__legacy__".into(),proof:token.to_string(),operation:operation.into(),args},&harness)
    }).unwrap_or_else(|_|ipc::result_error("invalid_request","Invalid compatibility request"));
    let bytes = serde_json::to_vec(&response).unwrap_or_default();
    let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",bytes.len());
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&bytes);
}
fn read_request(stream: &mut TcpStream) -> Result<(String, String, Zeroizing<String>, Value), ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = [0u8; 4096];
    let end = loop {
        let n = stream.read(&mut chunk).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > 64 * 1024 {
            return Err(());
        }
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..end]).map_err(|_| ())?;
    let mut lines = header.lines();
    let first = lines.next().ok_or(())?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or(())?.to_owned();
    let path = parts.next().ok_or(())?.to_owned();
    let mut token = Zeroizing::new(String::new());
    let mut length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("Authorization") {
                *token = value.trim().strip_prefix("Bearer ").ok_or(())?.to_owned();
            }
            if name.eq_ignore_ascii_case("Content-Length") {
                if length.is_some() {
                    return Err(());
                }
                length = Some(value.trim().parse::<usize>().map_err(|_| ())?);
            }
            if name.eq_ignore_ascii_case("Transfer-Encoding") || name.eq_ignore_ascii_case("Origin")
            {
                return Err(());
            }
        }
    }
    let length = length.unwrap_or(0);
    if length > ipc::MAX_MESSAGE {
        return Err(());
    }
    while bytes.len() < end + length {
        let n = stream.read(&mut chunk).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let body = if length == 0 {
        json!({})
    } else {
        serde_json::from_slice(&bytes[end..end + length]).map_err(|_| ())?
    };
    Ok((method, path, token, body))
}
