//! Human-operated migration and encrypted backup. No AI transport reaches these commands.
use crate::{
    lifecycle::atomic_write,
    service::{ensure_main, Shared},
};
use pman_core::{ipc, Vault};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tauri::{Emitter, State, WebviewWindow};
use zeroize::Zeroizing;

#[tauri::command]
pub async fn vault_backup(
    _app: tauri::AppHandle,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Option<Value>, String> {
    ensure_main(&window)?;
    let auth_epoch = {
        let mut management = state.management.lock().map_err(|_| "管理状态不可用")?;
        management.require_authenticated()?;
        management.auth_epoch
    };
    let owner = dialog_owner(&window)?;
    let picked = tauri::async_runtime::spawn_blocking(move || {
        crate::native_dialogs::save_file(owner, "保存加密保险库备份", "pman-backup.pman", "pman")
    })
    .await
    .map_err(|_| "无法打开保存窗口")??;
    let Some(path) = picked else { return Ok(None) };
    ensure_main(&window)?;
    let shared = state.inner().clone();
    let target = path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut management = shared.management.lock().map_err(|_| "管理状态不可用")?;
        management.require_authenticated()?;
        if management.auth_epoch != auth_epoch {
            return Err("管理界面曾锁定，请重新发起备份".into());
        }
        let core = shared.core.lock().map_err(|_| "服务状态不可用")?;
        if target.starts_with(&shared.home) {
            return Err("请选择保险库数据目录以外的位置保存备份".into());
        }
        core.vault
            .export_backup(&target)
            .map_err(|_| "备份失败，请检查目标路径；已有备份不会被覆盖".to_owned())
    })
    .await
    .map_err(|_| "备份任务失败")??;
    Ok(Some(json!({"path":path.display().to_string()})))
}
#[tauri::command]
pub async fn vault_import(
    password: String,
    source_path: Option<String>,
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Option<Value>, String> {
    import(password, source_path, false, app, window, state).await
}
#[tauri::command]
pub async fn vault_migrate_legacy(
    password: String,
    source_path: Option<String>,
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Option<Value>, String> {
    import(password, source_path, true, app, window, state).await
}

async fn import(
    password: String,
    source_path: Option<String>,
    legacy: bool,
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<Option<Value>, String> {
    ensure_main(&window)?;
    let password = Zeroizing::new(password);
    let initialized = state
        .core
        .lock()
        .map_err(|_| "服务状态不可用")?
        .vault
        .initialized()
        .map_err(|_| "无法读取保险库状态")?;
    if initialized {
        state.require_management()?;
    }
    let auth_epoch = state
        .management
        .lock()
        .map_err(|_| "管理状态不可用")?
        .auth_epoch;
    let source = if let Some(path) = source_path {
        PathBuf::from(path)
    } else {
        let owner = dialog_owner(&window)?;
        let picked = tauri::async_runtime::spawn_blocking(move || {
            crate::native_dialogs::pick_file(
                owner,
                if legacy {
                    "选择旧 pman vault.db"
                } else {
                    "选择 pman 加密备份"
                },
                if legacy { "db" } else { "pman" },
            )
        })
        .await
        .map_err(|_| "无法打开文件选择窗口")??;
        let Some(picked) = picked else {
            return Ok(None);
        };
        picked
    };
    ensure_main(&window)?;
    let start_legacy = legacy
        && !state
            .management
            .lock()
            .map_err(|_| "管理状态不可用")?
            .persistent
            .settings
            .legacy_http_enabled;
    let shared = state.inner().clone();
    let imported_from = source.display().to_string();
    let result=tauri::async_runtime::spawn_blocking(move||{
        if legacy&&std::net::TcpStream::connect_timeout(&"127.0.0.1:9777".parse().unwrap(),Duration::from_millis(250)).is_ok(){return Err("旧代理仍在运行或兼容端口被占用，请关闭旧代理后再迁移".to_owned())}
        let mut management=shared.management.lock().map_err(|_|"管理状态不可用")?;
        if management.auth_epoch!=auth_epoch{return Err("管理界面曾锁定，请重新发起导入".to_owned());}
        if initialized{management.require_authenticated()?;}
        let mut core=shared.core.lock().map_err(|_|"服务状态不可用")?;
        if core.vault.initialized().map_err(|_|"无法读取保险库状态")? {management.require_authenticated()?;}
        let source=source.canonicalize().map_err(|_|"导入文件不存在")?;
        if source==core.vault.db_path().canonicalize().map_err(|_|"无法检查导入路径")?{return Err("不能将正在使用的保险库作为导入源".into())}
        let staging=shared.home.join(format!("import-{}",uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&staging).map_err(|_|"无法创建导入目录")?;
        let imported=if legacy{Vault::import_snapshot(&source,&staging,&password,false)}else{Vault::import_backup(&source,&staging,&password)};
        let imported=match imported{Ok(v)=>v,Err(_)=>{cleanup_staging(&staging,&shared.home);return Err("无法导入：请检查原主密码、备份完整性和加密参数".into())}};
        let key=imported.export_resume_key().map_err(|_|"无法验证导入保险库")?;
        let wrapped=ipc::protect(&key).map_err(|_|"无法保护导入保险库的恢复材料")?;
        let count=imported.list_sites().map_err(|_|"无法读取导入项目")?.len();
        drop(imported);
        // Persist pause before changing live files. A failed installation always reopens
        // the original home locked and retains an independent before-import snapshot.
        management.set_paused(true)?;
        core.vault.lock();
        let old_directory=shared.home.join(format!("before-import-{}",uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&old_directory).map_err(|_|"无法创建恢复副本")?;
        let placeholder_directory=staging.join("placeholder");
        let placeholder=Vault::open(&placeholder_directory).map_err(|_|"无法准备迁移")?;
        let previous=std::mem::replace(&mut core.vault,placeholder);drop(previous);
        let previous_settings=management.persistent.settings.legacy_http_enabled;
        let old_material=shared.home.join("service-key.bin");
        let old_material_exists=old_material.is_file();
        let mut moved=Vec::new();
        let mut installed=false;
        let replacement=(||{
            if old_material_exists {fs::copy(&old_material,old_directory.join("service-key.bin")).map_err(|_|"无法保存迁移前恢复材料")?;}
            for name in ["vault.db","vault.db-wal","vault.db-shm"]{
                let old=shared.home.join(name);
                if old.exists(){fs::rename(&old,old_directory.join(name)).map_err(|_|"无法保存迁移前快照")?;moved.push(name.to_owned());}
            }
            fs::rename(staging.join("vault.db"),shared.home.join("vault.db")).map_err(|_|"无法安装导入快照")?;
            installed=true;
            let mut opened=Vault::open(&shared.home).map_err(|_|"无法打开导入快照")?;
            opened.resume_with_key(&key).map_err(|_|"导入快照验证失败")?;
            atomic_write(&old_material,&wrapped)?;
            core.vault=opened;
            management.persistent.settings.legacy_http_enabled=legacy || previous_settings;
            management.set_paused(false)?;management.authenticate();
            Ok::<(),String>(())
        })();
        if let Err(error)=replacement{
            // Close any new live handle before rollback. Never delete the selected source.
            let placeholder=Vault::open(&placeholder_directory).map_err(|_|"无法准备回滚；服务保持暂停")?;
            let displaced=std::mem::replace(&mut core.vault,placeholder);drop(displaced);
            let rollback=(||{
                rollback_files(&shared.home,&old_directory,&staging,&moved,installed,old_material_exists)?;
                core.vault=Vault::open(&shared.home).map_err(|_|"无法重新打开原保险库")?;
                Ok::<(),String>(())
            })();
            core.vault.lock();management.persistent.service_paused=true;
            management.persistent.settings.legacy_http_enabled=previous_settings;
            management.lock_interface();let _=management.save();
            let rollback_message=match rollback{Ok(())=>"原保险库已恢复并保持暂停".to_owned(),Err(problem)=>format!("{problem}；请使用迁移前副本恢复")};
            management.startup_error=Some(rollback_message.clone());
            return Err(format!("{error}。{rollback_message}，迁移前副本保存在 {}",old_directory.display()));
        }
        cleanup_staging(&staging,&shared.home);
        if !legacy{
            let clients=shared.home.join("clients");
            if clients.is_dir(){for entry in fs::read_dir(&clients).map_err(|_|"无法清理旧配对")?.flatten(){let path=entry.path();if path.extension().and_then(|v|v.to_str())==Some("cap"){let _=fs::remove_file(path);}}}
        }
        Ok(json!({"path":imported_from,"detail":format!("已导入 {count} 项；{}",if legacy{"原保险库已保留"}else{"请重新配对 AI 客户端"})}))
    }).await.map_err(|_|"导入任务失败")??;
    if start_legacy {
        crate::legacy_http::start(state.inner().clone());
    }
    let _ = app.emit("service-changed", ());
    let _ = app.emit("connections-changed", ());
    Ok(Some(result))
}
fn rollback_files(
    home: &Path,
    before: &Path,
    staging: &Path,
    moved: &[String],
    installed: bool,
    old_material_exists: bool,
) -> Result<(), String> {
    if installed {
        let failed = staging.join("failed-import");
        fs::create_dir_all(&failed).map_err(|_| "无法保存失败的导入快照")?;
        for name in ["vault.db", "vault.db-wal", "vault.db-shm"] {
            let current = home.join(name);
            if current.exists() {
                fs::rename(current, failed.join(name)).map_err(|_| "无法移出失败的导入快照")?;
            }
        }
    }
    for name in moved {
        fs::copy(before.join(name), home.join(name)).map_err(|_| "无法恢复原保险库文件")?;
    }
    let material = home.join("service-key.bin");
    if old_material_exists && before.join("service-key.bin").is_file() {
        let protected =
            fs::read(before.join("service-key.bin")).map_err(|_| "无法恢复本机解锁材料")?;
        atomic_write(&material, &protected)?;
    } else if !old_material_exists && material.exists() {
        fs::remove_file(&material).map_err(|_| "无法清除未完成的恢复材料")?;
    }
    Ok(())
}

#[cfg(windows)]
fn dialog_owner(window: &WebviewWindow) -> Result<isize, String> {
    Ok(window.hwnd().map_err(|_| "无法关联主窗口")?.0 as isize)
}
#[cfg(not(windows))]
fn dialog_owner(_window: &WebviewWindow) -> Result<isize, String> {
    Ok(0)
}

fn cleanup_staging(path: &Path, home: &Path) {
    let valid_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("import-"))
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok());
    if !valid_name || path.parent() != Some(home) {
        return;
    }
    let (Ok(resolved), Ok(root)) = (path.canonicalize(), home.canonicalize()) else {
        return;
    };
    if resolved.parent() == Some(root.as_path()) {
        let _ = fs::remove_dir_all(resolved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_replacement_restores_original_and_retains_both_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let before = root.path().join("before");
        let staging = root.path().join("staging");
        fs::create_dir(&before).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::write(root.path().join("vault.db"), b"new database").unwrap();
        fs::write(
            root.path().join("service-key.bin"),
            b"new protected material",
        )
        .unwrap();
        fs::write(before.join("vault.db"), b"old database").unwrap();
        fs::write(before.join("service-key.bin"), b"old protected material").unwrap();
        rollback_files(
            root.path(),
            &before,
            &staging,
            &["vault.db".to_owned()],
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("vault.db")).unwrap(),
            b"old database"
        );
        assert_eq!(
            fs::read(root.path().join("service-key.bin")).unwrap(),
            b"old protected material"
        );
        assert_eq!(fs::read(before.join("vault.db")).unwrap(), b"old database");
        assert_eq!(
            fs::read(staging.join("failed-import/vault.db")).unwrap(),
            b"new database"
        );
    }
    #[test]
    fn cleanup_only_removes_an_exact_uuid_staging_directory() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("import-important");
        fs::create_dir(&saved).unwrap();
        cleanup_staging(&saved, root.path());
        assert!(saved.exists());
        let staged = root.path().join(format!("import-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&staged).unwrap();
        cleanup_staging(&staged, root.path());
        assert!(!staged.exists());
    }
}
