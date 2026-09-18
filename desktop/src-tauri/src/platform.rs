//! Native user-presence, startup, clipboard and session notifications.
use std::path::Path;

#[cfg(windows)]
struct WinRtApartment;
#[cfg(windows)]
impl WinRtApartment {
    fn initialize() -> Result<Self, String> {
        unsafe {
            windows::Win32::System::WinRT::RoInitialize(
                windows::Win32::System::WinRT::RO_INIT_MULTITHREADED,
            )
        }
        .map_err(|_| "无法初始化 Windows 身份验证".to_owned())?;
        Ok(Self)
    }
}
#[cfg(windows)]
impl Drop for WinRtApartment {
    fn drop(&mut self) {
        unsafe {
            windows::Win32::System::WinRT::RoUninitialize();
        }
    }
}

#[cfg(windows)]
pub fn hello_available() -> bool {
    let Ok(_apartment) = WinRtApartment::initialize() else {
        return false;
    };
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };
    UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.get())
        .map(|v| v == UserConsentVerifierAvailability::Available)
        .unwrap_or(false)
}
#[cfg(not(windows))]
pub fn hello_available() -> bool {
    false
}

#[cfg(windows)]
pub fn verify_hello(hwnd: isize) -> Result<(), String> {
    let _apartment = WinRtApartment::initialize()?;
    use windows::{
        core::{factory, HSTRING},
        Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier},
        Win32::{Foundation::HWND, System::WinRT::IUserConsentVerifierInterop},
    };
    use windows_future::IAsyncOperation;
    let verifier: IUserConsentVerifierInterop =
        factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|_| "Windows Hello 不可用，请使用主密码")?;
    let operation: IAsyncOperation<UserConsentVerificationResult> = unsafe {
        verifier.RequestVerificationForWindowAsync(
            HWND(hwnd as *mut _),
            &HSTRING::from("验证身份以管理 pman 凭据和授权"),
        )
    }
    .map_err(|_| "无法启动 Windows Hello，请使用主密码")?;
    let result = operation.get().map_err(|_| "Windows Hello 验证未完成")?;
    if result == UserConsentVerificationResult::Verified {
        Ok(())
    } else {
        Err("未通过 Windows Hello 验证，管理界面保持锁定".into())
    }
}
#[cfg(not(windows))]
pub fn verify_hello(_hwnd: isize) -> Result<(), String> {
    Err("此平台不支持 Windows Hello".into())
}

#[cfg(windows)]
pub fn set_autostart(enabled: bool, executable: &Path) -> Result<(), String> {
    use windows::{
        core::{w, PCWSTR},
        Win32::System::Registry::*,
    };
    if std::env::var_os("PM_NATIVE_HOME").is_some() {
        return Ok(());
    } // Isolated test instances never alter the user's startup configuration.
    let mut key = HKEY::default();
    unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
        .ok()
        .map_err(|_| "无法更新登录启动设置")?;
        let result = if enabled {
            let command = format!("\"{}\" --background", executable.display());
            let wide: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
            let bytes = std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * 2);
            RegSetValueExW(key, w!("pman"), Some(0), REG_SZ, Some(bytes)).ok()
        } else {
            let status = RegDeleteValueW(key, PCWSTR(w!("pman").as_ptr()));
            if status.0 == 2 {
                Ok(())
            } else {
                status.ok()
            }
        };
        let _ = RegCloseKey(key);
        result.map_err(|_| "无法更新登录启动设置".to_owned())
    }
}
#[cfg(not(windows))]
pub fn set_autostart(_enabled: bool, _executable: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
pub fn idle_seconds() -> u64 {
    use windows::Win32::{
        System::SystemInformation::GetTickCount,
        UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
    };
    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        if GetLastInputInfo(&mut info).as_bool() {
            GetTickCount().wrapping_sub(info.dwTime) as u64 / 1000
        } else {
            0
        }
    }
}
#[cfg(not(windows))]
pub fn idle_seconds() -> u64 {
    0
}

/// Only real Windows input while this app is foreground extends management activity.
#[cfg(windows)]
pub fn management_input(app: &tauri::AppHandle) -> Option<u32> {
    use tauri::Manager;
    use windows::Win32::UI::{
        Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
        WindowsAndMessaging::GetForegroundWindow,
    };
    let foreground = unsafe { GetForegroundWindow() };
    let ours = app.webview_windows().values().any(|window| {
        window
            .hwnd()
            .ok()
            .is_some_and(|hwnd| hwnd.0 == foreground.0)
    });
    if !ours {
        return None;
    }
    let mut input = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        GetLastInputInfo(&mut input)
            .as_bool()
            .then_some(input.dwTime)
    }
}
#[cfg(not(windows))]
pub fn management_input(_app: &tauri::AppHandle) -> Option<u32> {
    None
}

#[cfg(windows)]
pub fn copy_secret(text: &str) -> Result<(), String> {
    use windows::Win32::{
        Foundation::HANDLE,
        System::{DataExchange::*, Memory::*},
    };
    use zeroize::Zeroize;
    let mut wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let allocation =
            GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2).map_err(|_| "无法分配剪贴板内存")?;
        let pointer = GlobalLock(allocation);
        if pointer.is_null() {
            let _ = windows::Win32::Foundation::GlobalFree(Some(allocation));
            return Err("无法写入剪贴板".into());
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), pointer.cast::<u16>(), wide.len());
        wide.zeroize();
        let _ = GlobalUnlock(allocation);
        if OpenClipboard(None).is_err() {
            let _ = windows::Win32::Foundation::GlobalFree(Some(allocation));
            return Err("剪贴板正忙，请重试".into());
        }
        let result =
            EmptyClipboard().and_then(|_| SetClipboardData(13, Some(HANDLE(allocation.0))));
        let sequence = GetClipboardSequenceNumber();
        let _ = CloseClipboard();
        if result.is_err() {
            let _ = windows::Win32::Foundation::GlobalFree(Some(allocation));
            return Err("无法写入剪贴板".into());
        }
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if GetClipboardSequenceNumber() == sequence && OpenClipboard(None).is_ok() {
                if GetClipboardSequenceNumber() == sequence {
                    let _ = EmptyClipboard();
                }
                let _ = CloseClipboard();
            }
        });
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn copy_secret(_text: &str) -> Result<(), String> {
    Err("此平台的原生剪贴板暂不可用".into())
}

#[cfg(windows)]
pub fn watch_session(
    window: &tauri::WebviewWindow,
    lock: impl Fn() + Send + Sync + 'static,
) -> Result<(), String> {
    use windows::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::RemoteDesktop::*,
        UI::{
            Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
            WindowsAndMessaging::*,
        },
    };
    type Callback = Box<dyn Fn() + Send + Sync>;
    unsafe extern "system" fn subclass(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        id: usize,
        data: usize,
    ) -> LRESULT {
        if (message == WM_WTSSESSION_CHANGE && wparam.0 == WTS_SESSION_LOCK as usize)
            || (message == WM_POWERBROADCAST && matches!(wparam.0, 4 | 7 | 18))
        {
            let callback = &*(data as *const Callback);
            callback();
        }
        if message == WM_NCDESTROY {
            let _ = RemoveWindowSubclass(hwnd, Some(subclass), id);
            drop(Box::from_raw(data as *mut Callback));
        }
        DefSubclassProc(hwnd, message, wparam, lparam)
    }
    let hwnd = window.hwnd().map_err(|_| "无法监听 Windows 会话")?;
    let callback: Box<Callback> = Box::new(Box::new(lock));
    let pointer = Box::into_raw(callback);
    unsafe {
        if !SetWindowSubclass(HWND(hwnd.0), Some(subclass), 0x706d616e, pointer as usize).as_bool()
        {
            drop(Box::from_raw(pointer));
            return Err("无法监听 Windows 会话".into());
        }
        WTSRegisterSessionNotification(HWND(hwnd.0), NOTIFY_FOR_THIS_SESSION)
            .map_err(|_| "无法监听锁屏事件")?;
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn watch_session(
    _window: &tauri::WebviewWindow,
    _lock: impl Fn() + Send + Sync + 'static,
) -> Result<(), String> {
    Ok(())
}
