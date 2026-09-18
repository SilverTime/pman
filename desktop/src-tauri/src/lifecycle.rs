//! Management authentication and the resident credential service have independent lifetimes.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub autostart: bool,
    pub idle_lock_minutes: u32,
    pub theme: String,
    pub reduced_motion: bool,
    pub hello_enabled: bool,
    pub legacy_http_enabled: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            autostart: true,
            idle_lock_minutes: 15,
            theme: "light".into(),
            reduced_motion: false,
            hello_enabled: true,
            legacy_http_enabled: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PersistentState {
    pub service_paused: bool,
    pub settings: Settings,
}
pub struct ManagementState {
    pub persistent: PersistentState,
    pub authenticated: bool,
    pub last_activity: Instant,
    pub hello_available: bool,
    pub startup_error: Option<String>,
    pub auth_epoch: u64,
    path: PathBuf,
}
impl ManagementState {
    pub fn open(home: &Path) -> Result<Self, String> {
        let path = home.join("desktop-state.json");
        let (persistent, startup_error) = if path.exists() {
            match fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            {
                Some(value) => (value, None),
                None => (
                    PersistentState {
                        service_paused: true,
                        ..Default::default()
                    },
                    Some("服务状态文件无法读取，已保持暂停；请验证身份并主动恢复".into()),
                ),
            }
        } else {
            (PersistentState::default(), None)
        };
        Ok(Self {
            persistent,
            authenticated: false,
            last_activity: Instant::now(),
            hello_available: false,
            startup_error,
            auth_epoch: 0,
            path,
        })
    }
    pub fn save(&self) -> Result<(), String> {
        atomic_write(
            &self.path,
            &serde_json::to_vec_pretty(&self.persistent).map_err(|_| "无法保存服务状态")?,
        )
    }
    pub fn require_authenticated(&mut self) -> Result<(), String> {
        if !self.authenticated {
            return Err("management_locked: 请先解锁管理界面，AI 服务不受影响".into());
        }
        Ok(())
    }
    pub fn authenticate(&mut self) {
        self.authenticated = true;
        self.last_activity = Instant::now();
    }
    pub fn lock_interface(&mut self) {
        self.authenticated = false;
        self.auth_epoch = self.auth_epoch.wrapping_add(1);
    }
    pub fn set_paused(&mut self, paused: bool) -> Result<(), String> {
        let old = self.persistent.service_paused;
        self.persistent.service_paused = paused;
        if let Err(e) = self.save() {
            self.persistent.service_paused = old;
            return Err(e);
        }
        Ok(())
    }
    pub fn should_resume(&self) -> bool {
        !self.persistent.service_paused
    }
    pub fn idle_lock(&mut self, idle_seconds: u64) -> bool {
        let minutes = self.persistent.settings.idle_lock_minutes;
        if self.authenticated
            && minutes > 0
            && (idle_seconds >= u64::from(minutes) * 60
                || self.last_activity.elapsed().as_secs() >= u64::from(minutes) * 60)
        {
            self.lock_interface();
            true
        } else {
            false
        }
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "无法创建本机数据目录")?;
    }
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "无法写入本机设置")?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "无法写入本机设置")?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows::{
                core::PCWSTR,
                Win32::Storage::FileSystem::{
                    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
                },
            };
            let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            unsafe {
                MoveFileExW(
                    PCWSTR(from.as_ptr()),
                    PCWSTR(to.as_ptr()),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            }
            .map_err(|_| "无法更新本机设置")?;
        }
        #[cfg(not(windows))]
        fs::rename(&temporary, path).map_err(|_| "无法更新本机设置")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ui_lock_and_idle_never_pause_service() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ManagementState::open(dir.path()).unwrap();
        s.authenticate();
        s.lock_interface();
        assert!(s.should_resume());
        s.authenticate();
        assert!(s.idle_lock(901));
        assert!(s.should_resume());
    }
    #[test]
    fn explicit_pause_survives_restart_and_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ManagementState::open(dir.path()).unwrap();
        s.set_paused(true).unwrap();
        let mut reopened = ManagementState::open(dir.path()).unwrap();
        reopened.authenticate();
        assert!(!reopened.should_resume());
        reopened.set_paused(false).unwrap();
        assert!(ManagementState::open(dir.path()).unwrap().should_resume());
    }
    #[test]
    fn restart_keeps_management_locked_even_with_automatic_resume() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ManagementState::open(dir.path()).unwrap();
        s.authenticate();
        s.save().unwrap();
        let mut reopened = ManagementState::open(dir.path()).unwrap();
        assert!(reopened.should_resume());
        assert!(reopened.require_authenticated().is_err());
    }
    #[test]
    fn background_metadata_refresh_does_not_extend_management_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ManagementState::open(dir.path()).unwrap();
        s.authenticate();
        s.last_activity = Instant::now() - std::time::Duration::from_secs(901);
        s.require_authenticated().unwrap();
        assert!(s.idle_lock(0));
        assert!(s.should_resume());
    }
}
