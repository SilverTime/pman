//! One desktop broker per Windows user and workspace. Activation only reveals the existing window.
#[cfg(windows)]
mod windows_impl {
    use tauri::Manager;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0},
            System::Threading::{
                CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject,
                EVENT_MODIFY_STATE, INFINITE, SYNCHRONIZATION_SYNCHRONIZE,
            },
        },
    };

    /// Keep this local guard alive for the complete Tauri run, before opening any database.
    pub struct Guard {
        mutex: HANDLE,
        event: HANDLE,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.event);
                let _ = CloseHandle(self.mutex);
            }
        }
    }

    fn name() -> Result<String, String> {
        let pipe = pman_core::ipc::pipe_name().map_err(|_| "无法确定本机工作区标识")?;
        let id = pipe.rsplit('\\').next().ok_or("本机工作区标识无效")?;
        // Global prevents the same Windows account opening a second broker in another session.
        Ok(format!("Global\\{id}-desktop"))
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    pub fn acquire() -> Result<Option<Guard>, String> {
        acquire_named(&name()?, !std::env::args().any(|a| a == "--background"))
    }

    fn acquire_named(name: &str, activate: bool) -> Result<Option<Guard>, String> {
        let mutex_name = wide(name);
        let event_name = wide(&format!("{name}-activate"));
        unsafe {
            let mutex = CreateMutexW(None, false, PCWSTR(mutex_name.as_ptr()))
                .map_err(|_| "无法创建本机单实例保护")?;
            let exists = GetLastError() == ERROR_ALREADY_EXISTS;
            if exists {
                if activate {
                    // First launch creates this event before initializing Tauri. A queued signal
                    // survives startup and does not carry commands or credential data.
                    for _ in 0..20 {
                        if let Ok(event) =
                            OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(event_name.as_ptr()))
                        {
                            let _ = SetEvent(event);
                            let _ = CloseHandle(event);
                            break;
                        }
                        // The first process may have created its mutex immediately before us.
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                }
                let _ = CloseHandle(mutex);
                return Ok(None);
            }
            match CreateEventW(None, false, false, PCWSTR(event_name.as_ptr())) {
                Ok(event) => Ok(Some(Guard { mutex, event })),
                Err(_) => {
                    let _ = CloseHandle(mutex);
                    Err("无法创建本机窗口激活事件".into())
                }
            }
        }
    }

    /// Call at the end of setup, after applying the initial --background visibility.
    pub fn attach(app: tauri::AppHandle) -> Result<(), String> {
        let event_name = wide(&format!("{}-activate", name()?));
        let event = unsafe {
            OpenEventW(
                SYNCHRONIZATION_SYNCHRONIZE,
                false,
                PCWSTR(event_name.as_ptr()),
            )
            .map_err(|_| "无法连接本机窗口激活事件")?
        };
        let raw = event.0 as usize;
        let result = std::thread::Builder::new()
            .name("pman-window-activation".into())
            .spawn(move || {
                let event = HANDLE(raw as *mut _);
                loop {
                    if unsafe { WaitForSingleObject(event, INFINITE) } != WAIT_OBJECT_0 {
                        break;
                    }
                    let application = app.clone();
                    if app
                        .run_on_main_thread(move || {
                            if let Some(window) = application.get_webview_window("main") {
                                let _ = window.unminimize();
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                unsafe {
                    let _ = CloseHandle(event);
                }
            });
        if result.is_err() {
            unsafe {
                let _ = CloseHandle(event);
            }
            return Err("无法启动本机窗口激活监听".into());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::Foundation::WAIT_TIMEOUT;

        #[test]
        fn duplicate_instance_only_signals_activation_and_release_allows_restart() {
            let name = format!("Global\\pman-synthetic-instance-{}", uuid::Uuid::new_v4());
            let first = acquire_named(&name, false).unwrap().unwrap();
            assert!(acquire_named(&name, false).unwrap().is_none());
            assert_eq!(unsafe { WaitForSingleObject(first.event, 0) }, WAIT_TIMEOUT);
            assert!(acquire_named(&name, true).unwrap().is_none());
            assert_eq!(
                unsafe { WaitForSingleObject(first.event, 100) },
                WAIT_OBJECT_0
            );
            drop(first);
            assert!(acquire_named(&name, false).unwrap().is_some());
        }
    }
}

#[cfg(windows)]
pub use windows_impl::{acquire, attach};

#[cfg(not(windows))]
pub struct Guard;
#[cfg(not(windows))]
pub fn acquire() -> Result<Option<Guard>, String> {
    Ok(Some(Guard))
}
#[cfg(not(windows))]
pub fn attach(_: tauri::AppHandle) -> Result<(), String> {
    Ok(())
}
