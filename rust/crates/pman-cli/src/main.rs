//! Native bridge only: never opens the credential database.
use pman_core::ipc;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let client = option(&args, "--client").or_else(|| std::env::var("PM_CLIENT").ok());
    if args.iter().any(|a| a == "--mcp") || positionals(&args).first().copied() == Some("mcp") {
        mcp(client.as_deref());
        return;
    }
    let response = match parse_command(&args) {
        Ok((operation, value)) => dispatch(client.as_deref(), &operation, value),
        Err(message) => ipc::result_error("invalid_request", &message),
    };
    let success = response.get("ok").and_then(Value::as_bool).unwrap_or(false);
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".into())
    );
    if !success {
        std::process::exit(1)
    }
}
fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn positionals(args: &[String]) -> Vec<&str> {
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            i += if args[i] == "--json-output" || args[i] == "--help" {
                1
            } else {
                2
            };
        } else {
            positional.push(args[i].as_str());
            i += 1;
        }
    }
    positional
}
fn parse_command(args: &[String]) -> Result<(String, Value), String> {
    if args.iter().any(|a| a == "--stdin") {
        let mut bytes = Vec::new();
        io::stdin()
            .take((ipc::MAX_MESSAGE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read JSON input")?;
        if bytes.len() > ipc::MAX_MESSAGE {
            return Err("Request is too large".into());
        }
        let mut value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "Input must be a JSON object")?;
        let object = value.as_object_mut().ok_or("Input must be a JSON object")?;
        let operation = object
            .remove("operation")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or("operation is required")?;
        return Ok((operation, value));
    }
    let positional = positionals(args);
    let command = positional.first().copied().unwrap_or("ai-help");
    match command{
      "protocol"=>Ok(("protocol".into(),json!({}))),"ai-help"=>Ok(("contract".into(),json!({}))),
      "sites"=>Ok(("sites".into(),json!({}))),"status"=>Ok(("status".into(),json!({}))),
      "cred"=>match positional.get(1).copied(){Some("ls"|"list")=>Ok(("sites".into(),json!({}))),Some("status")=>Ok(("credential_status".into(),json!({"site":positional.get(2).ok_or("Credential alias required")?}))),_=>Err("Use cred ls or cred status <alias>".into())},
      "call"|"run"=>{
        let site=option(args,"--site").ok_or("--site is required")?;let method=option(args,"--method").unwrap_or_else(||"GET".into());let path=option(args,"--path").ok_or("--path is required")?;
        let mut request=json!({"site":site,"method":method,"path":path});
        if let Some(capability)=option(args,"--capability"){request["capability"]=capability.into();}
        if let Some(raw)=option(args,"--json"){request["json_body"]=serde_json::from_str(&raw).map_err(|_|"Invalid --json object")?;}
        for(flag,field)in[("--query","query"),("--form","form")]{let mut object=serde_json::Map::new();for pair in args.windows(2).filter(|w|w[0]==flag){let(key,value)=pair[1].split_once('=').ok_or("Expected K=V")?;object.insert(key.into(),value.into());}if !object.is_empty(){request[field]=object.into();}}
        Ok(("http".into(),json!({"request":request})))
      },
      "request-login"=>Ok(("request_login".into(),json!({"site":option(args,"--site").ok_or("--site is required")?,"reason":option(args,"--reason").unwrap_or_default()}))),
      "resolve"=>{
        let intent=option(args,"--intent").ok_or("--intent is required")?;
        let mut context=serde_json::Map::new();
        for pair in args.windows(2).filter(|w|w[0]=="--context") {let(key,value)=pair[1].split_once('=').ok_or("Expected K=V")?;context.insert(key.into(),value.into());}
        Ok(("resolve_scenario".into(),json!({"intent":intent,"context":context})))
      },
      "request-access"=>Ok(("request_access".into(),json!({"site":option(args,"--site").ok_or("--site is required")?,"reason":option(args,"--reason").unwrap_or_default(),"requested_scope":{"method":option(args,"--method").ok_or("--method is required")?,"path":option(args,"--path").ok_or("--path is required")?,"operation":option(args,"--operation").ok_or("--operation query or write is required")?}}))),
      "request-status"=>Ok(("request_status".into(),json!({"req_id":positional.get(1).ok_or("Request id required")?}))),
      "approval-wait"=>Ok(("approval_wait".into(),json!({"req_id":positional.get(1).ok_or("Request id required")?,"timeout_sec":option(args,"--timeout").and_then(|v|v.parse::<u64>().ok()).unwrap_or(60)}))),
      _=>Err("Use ai-help, sites, resolve, cred status, call, status, --stdin or mcp. Manage credentials and approvals in pman desktop.".into())
    }
}
fn dispatch(client: Option<&str>, operation: &str, mut args: Value) -> Value {
    if operation == "approval_wait" {
        if let Some(args) = args.as_object_mut() {
            args.entry("timeout_sec").or_insert(json!(60));
        }
    }
    if operation == "contract" {
        return ipc::contract();
    }
    if operation == "protocol" {
        return ipc::result_ok(json!({}));
    }
    let Some(client) = client else {
        if let (Ok(url), Ok(token)) = (std::env::var("PM_DAEMON"), std::env::var("PM_TOKEN")) {
            if let Ok(daemon) = pman_core::DaemonClient::new(url, Some(token)) {
                let result = match operation {
                    "sites" => daemon.sites(),
                    "status" => daemon.status(),
                    "http" => match serde_json::from_value::<pman_core::HttpRequest>(
                        args.get("request").cloned().unwrap_or(args.clone()),
                    ) {
                        Ok(request) => daemon.http(&request),
                        Err(_) => {
                            return ipc::result_error("invalid_request", "Invalid HTTP request")
                        }
                    },
                    _ => {
                        return ipc::result_error(
                            "invalid_request",
                            "Pair a native client to use this operation",
                        )
                    }
                };
                return result.unwrap_or_else(|_| {
                    ipc::result_error("request_failed", "Local legacy broker unavailable")
                });
            }
        }
        return ipc::result_error(
            "harness_invalid",
            "Pair this client in pman desktop, then use --client <client-id>",
        );
    };
    let call = || ipc::call(client, operation, args.clone());
    let mut result = call();
    if result
        .as_ref()
        .err()
        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
        && start_desktop()
    {
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            result = call();
            if !result
                .as_ref()
                .err()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
            {
                break;
            }
        }
    }
    // The desktop already performs the bounded approval wait. Repeating it here
    // would make one requested timeout last twice as long.
    result.unwrap_or_else(|_|ipc::result_error("broker_unavailable","Local broker or client identity unavailable. A sent request is never automatically retried; inspect activity before repeating a write."))
}
fn start_desktop() -> bool {
    let Some(path) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("pman-desktop.exe")))
        .filter(|p| p.is_file())
    else {
        return false;
    };
    let mut command = std::process::Command::new(path);
    command
        .arg("--background")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.spawn().is_ok()
}
fn tools_list() -> Value {
    json!({"tools":[
     {"name":"pm_contract","description":"Read the pman AI contract and credential boundaries.","inputSchema":{"type":"object","properties":{}}},
     {"name":"pm_sites","description":"List callable connection aliases and non-secret metadata.","inputSchema":{"type":"object","properties":{}}},
     {"name":"pm_status","description":"Read background authorization service status.","inputSchema":{"type":"object","properties":{}}},
     {"name":"pm_resolve_scenario","description":"Resolve a configured business intent and string context to exactly one connection and capability. Ambiguous or missing context never selects an account automatically.","inputSchema":{"type":"object","properties":{"intent":{"type":"string"},"context":{"type":"object","additionalProperties":{"type":"string"}}},"required":["intent"]}},
     {"name":"pm_http","description":"Call a granted connection. Credentials are injected locally and responses redacted. Include the resolved capability when using a business scenario. pending_approval requires a human decision in desktop.","inputSchema":{"type":"object","properties":{"site":{"type":"string"},"method":{"type":"string","enum":["GET","POST","PUT","PATCH","DELETE"]},"path":{"type":"string"},"capability":{"type":"string"},"query":{"type":"object"},"json_body":{"type":"object"},"form":{"type":"object"}},"required":["site","method","path"]}},
     {"name":"pm_approval_wait","description":"Wait up to 60 seconds for a human approval. Cannot approve requests.","inputSchema":{"type":"object","properties":{"req_id":{"type":"string"},"timeout_sec":{"type":"integer","minimum":0,"maximum":60}},"required":["req_id"]}},
     {"name":"pm_request_login","description":"Ask the user to refresh a granted connection's login in desktop. Never starts login or unlocks credentials by itself.","inputSchema":{"type":"object","properties":{"site":{"type":"string"},"reason":{"type":"string","maxLength":1000}},"required":["site"]}},
     {"name":"pm_request_access","description":"Request a human-reviewed scope for an explicitly known AI-enabled connection. This does not grant access.","inputSchema":{"type":"object","properties":{"site":{"type":"string"},"reason":{"type":"string","maxLength":1000},"requested_scope":{"type":"object","properties":{"method":{"type":"string","enum":["GET","POST","PUT","PATCH","DELETE"]},"path":{"type":"string"},"operation":{"type":"string","enum":["query","write"]}},"required":["method","path","operation"]}},"required":["site","requested_scope"]}},
     {"name":"pm_request_status","description":"Read the pending, handled or cancelled state of your assistance request. Handled does not itself prove login or grant success.","inputSchema":{"type":"object","properties":{"req_id":{"type":"string"}},"required":["req_id"]}},
     {"name":"pm_connection_status","description":"Read connection authentication state without secrets.","inputSchema":{"type":"object","properties":{"site":{"type":"string"}},"required":["site"]}},
     {"name":"pm_browser_open","description":"Open an independently authorized pman web session for a connection.","inputSchema":{"type":"object","properties":{"site":{"type":"string"}},"required":["site"]}},
     {"name":"pm_browser_summary","description":"Read a sanitized page summary from a pman web session.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}},
     {"name":"pm_browser_click","description":"Follow a same-origin navigation link. Buttons, form submissions, downloads and consequential actions are unsupported.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"},"selector":{"type":"string"}},"required":["session_id","selector"]}},
     {"name":"pm_browser_fill","description":"Fill a non-sensitive field. Password, OTP, token and payment fields are always rejected.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"},"selector":{"type":"string"},"value":{"type":"string"}},"required":["session_id","selector","value"]}},
     {"name":"pm_browser_wait","description":"Wait for a selector or visible text in a pman web session.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"},"selector":{"type":"string"},"text":{"type":"string"},"timeout_ms":{"type":"integer","minimum":0,"maximum":10000}},"required":["session_id"]}},
     {"name":"pm_browser_close","description":"Close a pman web session.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}}
    ]})
}
fn mcp(client: Option<&str>) {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut bytes = Vec::new();
        let size = input
            .by_ref()
            .take((ipc::MAX_MESSAGE + 1) as u64)
            .read_until(b'\n', &mut bytes);
        if matches!(size, Ok(0) | Err(_)) {
            break;
        }
        if bytes.len() > ipc::MAX_MESSAGE {
            break;
        }
        let response = match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) => handle_rpc(client, value),
            Err(_) => Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
            ),
        };
        if let Some(response) = response {
            if writeln!(output, "{}", response)
                .and_then(|_| output.flush())
                .is_err()
            {
                break;
            }
        }
    }
}
fn handle_rpc(client: Option<&str>, value: Value) -> Option<Value> {
    let id = value.get("id")?.clone();
    let result = match value.get("method").and_then(Value::as_str).unwrap_or("") {
        "initialize" => {
            json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"pman-native","version":"0.4.0"}})
        }
        "ping" => json!({}),
        "tools/list" => tools_list(),
        "tools/call" => {
            let params = value.get("params").cloned().unwrap_or(json!({}));
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let operation = match params.get("name").and_then(Value::as_str).unwrap_or("") {
                "pm_contract" => "contract",
                "pm_sites" => "sites",
                "pm_status" => "status",
                "pm_resolve_scenario" => "resolve_scenario",
                "pm_http" => "http",
                "pm_approval_wait" => "approval_wait",
                "pm_connection_status" => "credential_status",
                "pm_request_login" => "request_login",
                "pm_request_access" => "request_access",
                "pm_request_status" => "request_status",
                "pm_browser_open" => "browser_open",
                "pm_browser_summary" => "browser_summary",
                "pm_browser_click" => "browser_click",
                "pm_browser_fill" => "browser_fill",
                "pm_browser_wait" => "browser_wait",
                "pm_browser_close" => "browser_close",
                _ => "unsupported",
            };
            let args = if operation == "http" {
                json!({"request":args})
            } else {
                args
            };
            let response = dispatch(client, operation, args);
            json!({"content":[{"type":"text","text":response.to_string()}],"isError":response.get("ok")==Some(&Value::Bool(false))})
        }
        _ => {
            return Some(
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}),
            )
        }
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_has_no_management_tools() {
        let text = tools_list().to_string();
        assert!(!text.contains("pm_approve"));
        assert!(!text.contains("pm_unlock"));
        assert!(text.contains("pm_resolve_scenario"));
        assert!(text.contains("pm_browser_open"));
        assert!(text.contains("pm_browser_close"));
    }
    #[test]
    fn notification_has_no_reply() {
        assert!(handle_rpc(
            None,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none());
    }
    #[test]
    fn structured_http_cli() {
        let args = [
            "--client",
            "example",
            "call",
            "--site",
            "Connection dev",
            "--method",
            "GET",
            "--path",
            "/me",
            "--capability",
            "profile.read",
            "--query",
            "x=1",
        ]
        .map(str::to_owned);
        let (op, args) = parse_command(&args).unwrap();
        assert_eq!(op, "http");
        assert_eq!(args["request"]["query"]["x"], "1");
        assert_eq!(args["request"]["capability"], "profile.read");
    }
    #[test]
    fn scenario_cli_keeps_context_structured() {
        let args = [
            "--client",
            "example",
            "resolve",
            "--intent",
            "jenkins.build",
            "--context",
            "service=web-api",
            "--context",
            "environment=test",
        ]
        .map(str::to_owned);
        let (op, args) = parse_command(&args).unwrap();
        assert_eq!(op, "resolve_scenario");
        assert_eq!(args["context"]["service"], "web-api");
        assert_eq!(args["context"]["environment"], "test");
    }
}
