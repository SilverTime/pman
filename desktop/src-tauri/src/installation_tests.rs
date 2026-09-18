//! Explicit release-binary acceptance, never run against the user's normal vault.
#![cfg(windows)]
use crate::service::Shared;
use pman_core::{ipc, SiteInput};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::windows::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const SYNTHETIC: &str = "SYNTHETIC_ACCEPTANCE_SECRET_5427189";
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Environment(Option<std::ffi::OsString>);
impl Drop for Environment {
    fn drop(&mut self) {
        if let Some(old) = self.0.take() {
            std::env::set_var("PM_NATIVE_HOME", old)
        } else {
            std::env::remove_var("PM_NATIVE_HOME")
        }
    }
}
fn command(exe: &Path, home: &Path) -> Command {
    let mut command = Command::new(exe);
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    command
        .env("PM_NATIVE_HOME", home)
        .env("PATH", Path::new(&system).join("System32"))
        .env_remove("PM_DAEMON")
        .env_remove("PM_TOKEN")
        .env_remove("PM_CLIENT");
    command
        .creation_flags(0x08000000)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn output(mut command: Command, input: &str) -> String {
    let mut child = Process(command.spawn().expect("start native CLI"));
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = String::new();
        stdout.read_to_string(&mut bytes).unwrap();
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = String::new();
        stderr.read_to_string(&mut bytes).unwrap();
        bytes
    });
    let until = Instant::now() + Duration::from_secs(30);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < until, "native CLI exceeded deadline");
        std::thread::sleep(Duration::from_millis(20));
    }
    let text = out.join().unwrap();
    let errors = err.join().unwrap();
    assert!(
        !text.contains(SYNTHETIC),
        "synthetic secret leaked in stdout"
    );
    assert!(
        !errors.contains(SYNTHETIC),
        "synthetic secret leaked in stderr"
    );
    text
}
fn call(cli: &Path, home: &Path, value: Value) -> Value {
    let mut cmd = command(cli, home);
    cmd.args(["--client", "acceptance", "--stdin"]);
    serde_json::from_str(&output(cmd, &value.to_string())).expect("CLI returned a JSON envelope")
}

#[test]
#[ignore = "requires explicit PM_ACCEPTANCE_DESKTOP and PM_ACCEPTANCE_CLI release binary paths"]
fn installed_binaries_work_without_python_rust_or_legacy_pm() {
    let desktop = std::env::var_os("PM_ACCEPTANCE_DESKTOP").expect("release desktop path required");
    let cli = std::env::var_os("PM_ACCEPTANCE_CLI").expect("release CLI path required");
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("synthetic-home");
    let bin = temp.path().join("program");
    fs::create_dir_all(&bin).unwrap();
    let desktop_path = bin.join("pman-desktop.exe");
    let cli_path = bin.join("pm.exe");
    fs::copy(desktop, &desktop_path).unwrap();
    fs::copy(cli, &cli_path).unwrap();
    let _environment = Environment(std::env::var_os("PM_NATIVE_HOME"));
    std::env::set_var("PM_NATIVE_HOME", &home);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let shared = Shared::open_at(home.clone()).unwrap();
    {
        let mut core = shared.core.lock().unwrap();
        core.vault.create("synthetic-acceptance-master").unwrap();
        core.vault
            .add_site(SiteInput::new(
                "fixture",
                &origin,
                "api_token",
                json!({"token":SYNTHETIC}),
            ))
            .unwrap();
        core.vault
            .update_details("fixture", json!({"ai_enabled":true}))
            .unwrap();
        core.vault.ensure_harness("acceptance").unwrap();
        core.vault.set_policy("acceptance",json!({"allow":[{"site":"fixture","methods":["GET"],"paths":["/query","/echo"],"require_approval":false}]})).unwrap();
        let verifier = ipc::create_pairing("acceptance").unwrap();
        core.vault
            .pair_client_for(
                "Synthetic acceptance",
                "generic",
                "acceptance",
                "acceptance",
                &verifier,
            )
            .unwrap();
    }
    shared
        .resume_password("synthetic-acceptance-master")
        .unwrap();
    drop(shared);
    let server = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(60);
        let mut count = 0;
        while count < 2 && Instant::now() < until {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0u8; 8192];
            let size = stream.read(&mut request).unwrap();
            let text = String::from_utf8_lossy(&request[..size]);
            assert!(text.contains(SYNTHETIC));
            let body = if text.starts_with("GET /echo") {
                json!({"echo":SYNTHETIC})
            } else {
                json!({"ready":true})
            }
            .to_string();
            let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            stream.write_all(response.as_bytes()).unwrap();
            count += 1;
        }
        count
    });
    let mut start = command(&desktop_path, &home);
    start.arg("--background").stdin(Stdio::null());
    let mut desktop = Process(start.spawn().unwrap());
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            desktop.0.try_wait().unwrap().is_none(),
            "desktop terminated during startup"
        );
        if ipc::call("acceptance", "status", json!({}))
            .ok()
            .is_some_and(|v| v["service_running"] == true)
        {
            break;
        }
        assert!(Instant::now() < until, "resident broker did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    let status = call(&cli_path, &home, json!({"operation":"status"}));
    assert_eq!(status["service_running"], true);
    assert_eq!(status["management_locked"], true);
    let result = call(
        &cli_path,
        &home,
        json!({"operation":"http","request":{"site":"fixture","method":"GET","path":"/query"}}),
    );
    assert_eq!(result["ok"], true);
    let mut mcp = command(&cli_path, &home);
    mcp.args(["mcp", "--client", "acceptance"]);
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pm_http","arguments":{"site":"fixture","method":"GET","path":"/echo"}}}),
    ];
    let text = output(
        mcp,
        &frames
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .add_newline(),
    );
    let replies = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "pman-native");
    assert!(replies[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "pm_request_login"));
    assert_eq!(server.join().unwrap(), 2);
    drop(desktop);
    let shared = Shared::open_at(home.clone()).unwrap();
    shared.pause().unwrap();
    drop(shared);
    let mut start = command(&desktop_path, &home);
    start.arg("--background").stdin(Stdio::null());
    let _paused = Process(start.spawn().unwrap());
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(value) = ipc::call("acceptance", "status", json!({})) {
            assert_eq!(value["service_paused"], true);
            assert_eq!(value["service_running"], false);
            break;
        }
        assert!(Instant::now() < until, "paused broker did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}
trait Newline {
    fn add_newline(self) -> String;
}
impl Newline for String {
    fn add_newline(mut self) -> String {
        self.push('\n');
        self
    }
}
