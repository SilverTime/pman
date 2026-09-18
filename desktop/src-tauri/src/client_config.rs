//! Targeted MCP configuration edits. Backups are DPAPI protected and never returned to the webview.
use crate::lifecycle::atomic_write;
use pman_core::ipc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize)]
pub struct ConfigPreview {
    pub path: String,
    pub content: String,
    pub exists: bool,
}
#[derive(Serialize)]
pub struct ConfigResult {
    pub path: String,
    pub backup_path: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Backup {
    path: String,
    existed: bool,
    before: Vec<u8>,
    installed_hash: String,
}

pub fn cli_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|_| "无法定位 pman 安装目录")?;
    let parent = exe.parent().ok_or("无法定位 pman 安装目录")?;
    let path = parent.join(if cfg!(windows) { "pm.exe" } else { "pm" });
    if path.is_file() {
        return Ok(path);
    }
    // cargo dev keeps the two binaries in distinct build directories.
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust/target/debug")
        .join(if cfg!(windows) { "pm.exe" } else { "pm" });
    if cfg!(debug_assertions) && dev.is_file() {
        Ok(dev)
    } else {
        Err("原生 pm 程序缺失，请修复安装或先构建 CLI".into())
    }
}
fn target(kind: &str, home: &Path) -> Result<PathBuf, String> {
    if std::env::var_os("PM_NATIVE_HOME").is_some() {
        return Ok(home.join("test-client-configs").join(if kind == "codex" {
            "config.toml"
        } else {
            "mcp.json"
        }));
    }
    let user = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .ok_or("无法定位当前用户目录")?;
    Ok(match kind {
        "codex" => user.join(".codex/config.toml"),
        "claude" => user.join(".claude.json"),
        _ => home.join("integrations/mcp.json"),
    })
}
fn id(client: &Value) -> Result<&str, String> {
    let value = client
        .get("id")
        .and_then(Value::as_str)
        .ok_or("客户端 ID 无效")?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("客户端 ID 无效".into());
    }
    Ok(value)
}
fn entry(client: &Value) -> Result<Value, String> {
    Ok(json!({"command":cli_path()?.to_string_lossy(),"args":["mcp","--client",id(client)?]}))
}
fn render(existing: &str, kind: &str, entry: &Value) -> Result<String, String> {
    if kind == "codex" {
        let parsed: toml::Value =
            toml::from_str(existing).map_err(|_| "现有 Codex 配置不是有效 TOML，已保留原文件")?;
        if parsed.get("mcp_servers").is_some_and(|v| !v.is_table()) {
            return Err("现有 MCP 配置结构无法安全更新".into());
        }
        let mut output = String::new();
        let mut skipping = false;
        let mut removed = false;
        for line in existing.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                // Parse each table header with the real TOML parser; support quoted keys as well.
                if let Ok(header) = toml::from_str::<toml::Value>(trimmed) {
                    skipping = header
                        .get("mcp_servers")
                        .and_then(|v| v.get("pman"))
                        .is_some();
                    if skipping {
                        removed = true;
                    }
                } else if skipping {
                    return Err("pman 配置包含复杂表结构，请人工调整后重试".into());
                }
            }
            if !skipping {
                output.push_str(line);
                output.push('\n');
            }
        }
        if parsed
            .get("mcp_servers")
            .and_then(|v| v.get("pman"))
            .is_some()
            && !removed
        {
            return Err("pman 使用了内联配置，请先在客户端中移除旧 pman 接入".into());
        }
        let command = serde_json::to_string(entry["command"].as_str().unwrap())
            .map_err(|_| "无法生成程序路径")?;
        let args = serde_json::to_string(&entry["args"]).map_err(|_| "无法生成启动参数")?;
        output.truncate(output.trim_end().len());
        output.push_str(&format!(
            "\n[mcp_servers.pman]\ncommand = {command}\nargs = {args}\n"
        ));
        let merged = toml::from_str::<toml::Value>(&output)
            .map_err(|_| "配置合并后未通过校验，已保留原文件")?;
        fn unrelated(mut value: toml::Value) -> toml::Value {
            if let Some(root) = value.as_table_mut() {
                if let Some(servers) = root
                    .get_mut("mcp_servers")
                    .and_then(toml::Value::as_table_mut)
                {
                    servers.remove("pman");
                    if servers.is_empty() {
                        root.remove("mcp_servers");
                    }
                }
            }
            value
        }
        if unrelated(parsed) != unrelated(merged) {
            return Err("现有配置含复杂结构，无法只更新 pman；已保留原文件".into());
        }
        Ok(output)
    } else {
        let mut document: Value = if existing.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(existing)
                .map_err(|_| "现有客户端配置不是有效 JSON，已保留原文件")?
        };
        let object = document.as_object_mut().ok_or("现有客户端配置结构无效")?;
        let servers = object
            .entry("mcpServers")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("现有 MCP 配置结构无法安全更新")?;
        servers.insert("pman".into(), entry.clone());
        serde_json::to_string_pretty(&document)
            .map(|v| format!("{v}\n"))
            .map_err(|_| "无法生成客户端配置".into())
    }
}
pub fn preview(client: &Value, home: &Path) -> Result<ConfigPreview, String> {
    let kind = client["kind"].as_str().unwrap_or("generic");
    let path = target(kind, home)?;
    Ok(ConfigPreview {
        path: path.display().to_string(),
        content: render("", kind, &entry(client)?)?,
        exists: path.exists(),
    })
}
pub fn apply(client: &Value, home: &Path) -> Result<ConfigResult, String> {
    let kind = client["kind"].as_str().unwrap_or("generic");
    let path = target(kind, home)?;
    let existed = path.exists();
    let before = Zeroizing::new(if existed {
        fs::read(&path).map_err(|_| "无法读取客户端配置")?
    } else {
        vec![]
    });
    let original = std::str::from_utf8(&before).map_err(|_| "客户端配置编码不受支持")?;
    let content = Zeroizing::new(render(original, kind, &entry(client)?)?);
    let backup_path = home
        .join("config-backups")
        .join(format!("{}.bin", id(client)?));
    if before.as_slice() == content.as_bytes() && backup_path.exists() {
        return Ok(ConfigResult {
            path: path.display().to_string(),
            backup_path: Some(backup_path.display().to_string()),
        });
    }
    let mut backup = Backup {
        path: path.display().to_string(),
        existed,
        before: before.to_vec(),
        installed_hash: hex::encode(Sha256::digest(content.as_bytes())),
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&backup).map_err(|_| "无法创建配置备份")?);
    backup.before.zeroize();
    let protected = ipc::protect(&encoded).map_err(|_| "无法保护配置备份")?;
    atomic_write(&backup_path, &protected)?;
    atomic_write(&path, content.as_bytes())?;
    Ok(ConfigResult {
        path: path.display().to_string(),
        backup_path: Some(backup_path.display().to_string()),
    })
}
pub fn restore(client: &Value, home: &Path) -> Result<ConfigResult, String> {
    let expected = target(client["kind"].as_str().unwrap_or("generic"), home)?;
    let backup_path = home
        .join("config-backups")
        .join(format!("{}.bin", id(client)?));
    let raw = fs::read(&backup_path).map_err(|_| "没有可恢复的配置备份")?;
    let plain = Zeroizing::new(ipc::unprotect(&raw).map_err(|_| "无法解密本机配置备份")?);
    let mut backup: Backup = serde_json::from_slice(&plain).map_err(|_| "配置备份损坏")?;
    if PathBuf::from(&backup.path) != expected {
        backup.before.zeroize();
        return Err("备份目标与当前客户端不一致".into());
    }
    let current = Zeroizing::new(fs::read(&expected).map_err(|_| "客户端配置已移动，请手动检查")?);
    if hex::encode(Sha256::digest(&current)) != backup.installed_hash {
        backup.before.zeroize();
        return Err("配置在接入后被其他程序修改，已保留当前文件，请人工合并".into());
    }
    let result = if backup.existed {
        atomic_write(&expected, &backup.before)
    } else {
        fs::remove_file(&expected).map_err(|_| "无法恢复配置".into())
    };
    backup.before.zeroize();
    result?;
    fs::remove_file(backup_path).map_err(|_| "配置已恢复，但无法移除旧备份")?;
    Ok(ConfigResult {
        path: expected.display().to_string(),
        backup_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Value {
        json!({"command":"C:\\pman\\pm.exe","args":["mcp","--client","test"]})
    }
    #[test]
    fn toml_preserves_unrelated_sections() {
        let text = render(
            "# user configuration\nmodel = 'custom'\n[mcp_servers.other]\ncommand = 'other'\n",
            "codex",
            &sample(),
        )
        .unwrap();
        assert!(text.contains("# user configuration"));
        assert!(text.contains("custom"));
        assert!(text.contains("mcp_servers.other"));
        assert!(text.contains("mcp_servers.pman"));
    }
    #[test]
    fn json_preserves_unrelated_sections() {
        let text = render(
            r#"{"theme":"dark","mcpServers":{"other":{"command":"other"}}}"#,
            "claude",
            &sample(),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["mcpServers"]["other"]["command"], "other");
    }
    #[test]
    fn repeated_toml_pairing_is_idempotent_and_keeps_original_backup_eligible() {
        let first = render("# original\nmodel='custom'\n", "codex", &sample()).unwrap();
        assert_eq!(render(&first, "codex", &sample()).unwrap(), first);
    }
    #[test]
    fn malformed_config_is_not_replaced() {
        assert!(render("oops [", "codex", &sample()).is_err());
        assert!(render("[1]", "claude", &sample()).is_err());
    }
    #[test]
    fn table_headers_inside_multiline_strings_do_not_change_other_settings() {
        let original =
            "note = '''\n[mcp_servers.pman]\ncommand = fake\n'''\n[tools]\nenabled = true\n";
        assert!(render(original, "codex", &sample()).is_err());
    }
    #[test]
    fn replaces_only_pman_and_preserves_following_tables() {
        let original="[mcp_servers.pman]\ncommand = 'old'\n[mcp_servers.pman.env]\nTEST = 'old'\n[mcp_servers.other]\ncommand = 'keep'\n";
        let result = render(original, "codex", &sample()).unwrap();
        let parsed: toml::Value = toml::from_str(&result).unwrap();
        assert_eq!(
            parsed["mcp_servers"]["other"]["command"].as_str(),
            Some("keep")
        );
        assert!(parsed["mcp_servers"]["pman"].get("env").is_none());
    }
}
