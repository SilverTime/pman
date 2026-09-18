//! Native Windows integration without external processes or cross-platform plugins.
use std::path::PathBuf;

#[cfg(windows)]
fn wide(value: &str) -> Result<Vec<u16>, String> {
    if value.contains('\0') {
        return Err("原生窗口参数无效".into());
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

pub fn pick_file(owner: isize, title: &str, extension: &str) -> Result<Option<PathBuf>, String> {
    file_dialog(owner, title, "", extension, false)
}

pub fn save_file(
    owner: isize,
    title: &str,
    suggested_name: &str,
    extension: &str,
) -> Result<Option<PathBuf>, String> {
    file_dialog(owner, title, suggested_name, extension, true)
}

#[cfg(windows)]
fn file_dialog(
    owner: isize,
    title: &str,
    suggested_name: &str,
    extension: &str,
    save: bool,
) -> Result<Option<PathBuf>, String> {
    use std::os::windows::ffi::OsStringExt;
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{Foundation::HWND, UI::Controls::Dialogs::*},
    };
    if extension.is_empty() || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("文件类型无效".into());
    }
    let title = wide(title)?;
    let extension_wide = wide(extension)?;
    let filter: Vec<u16> = format!("pman (*.{extension})\0*.{extension}\0所有文件\0*.*\0\0")
        .encode_utf16()
        .collect();
    let initial = wide(suggested_name)?;
    let mut file = vec![0u16; 32768];
    if initial.len() > file.len() {
        return Err("文件名过长".into());
    }
    file[..initial.len()].copy_from_slice(&initial);
    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: HWND(owner as *mut _),
        lpstrFilter: PCWSTR(filter.as_ptr()),
        nFilterIndex: 1,
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        lpstrDefExt: PCWSTR(extension_wide.as_ptr()),
        Flags: OFN_EXPLORER
            | OFN_NOCHANGEDIR
            | OFN_PATHMUSTEXIST
            | if save {
                OFN_OVERWRITEPROMPT
            } else {
                OFN_FILEMUSTEXIST
            },
        ..Default::default()
    };
    let selected = unsafe {
        if save {
            GetSaveFileNameW(&mut dialog)
        } else {
            GetOpenFileNameW(&mut dialog)
        }
    };
    if !selected.as_bool() {
        if unsafe { CommDlgExtendedError() }.0 != 0 {
            return Err("无法打开 Windows 文件选择窗口".into());
        }
        return Ok(None);
    }
    let length = file
        .iter()
        .position(|char| *char == 0)
        .ok_or("返回的文件路径无效")?;
    Ok(Some(PathBuf::from(std::ffi::OsString::from_wide(
        &file[..length],
    ))))
}

#[cfg(not(windows))]
fn file_dialog(
    _owner: isize,
    _title: &str,
    _suggested_name: &str,
    _extension: &str,
    _save: bool,
) -> Result<Option<PathBuf>, String> {
    Err("当前版本的原生文件选择仅支持 Windows".into())
}

pub fn open_external_url(url: &str) -> Result<(), String> {
    let parsed = tauri::Url::parse(url).map_err(|_| "浏览器地址无效")?;
    if !matches!(parsed.scheme(), "https" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str().is_none()
    {
        return Err("只能在浏览器中打开 HTTP 或 HTTPS 地址".into());
    }
    #[cfg(windows)]
    {
        use windows::{
            core::{w, PCWSTR},
            Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
        };
        let address = wide(parsed.as_str())?;
        let result = unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                PCWSTR(address.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if result.0 as isize <= 32 {
            return Err("无法打开系统浏览器".into());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("当前版本的浏览器授权仅支持 Windows".into())
    }
}

fn xml_text(text: &str) -> String {
    text.chars()
        .filter(|char| !char.is_control() || matches!(char, '\n' | '\t' | '\r'))
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
const APP_ID: &str = "com.pman.desktop";

/// Call from the resident service's background thread. No credentials enter toast XML.
#[cfg(windows)]
pub fn notify_open(app: tauri::AppHandle, title: &str, body: &str) -> Result<(), String> {
    notify_inner(title, body, Some(app))
}

#[cfg(windows)]
fn notify_inner(title: &str, body: &str, app: Option<tauri::AppHandle>) -> Result<(), String> {
    use windows::{
        core::HSTRING,
        Data::Xml::Dom::XmlDocument,
        Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
        UI::Notifications::{ToastNotification, ToastNotificationManager},
    };
    // Isolated test instances must not register shortcuts or notify the real user.
    if std::env::var_os("PM_NATIVE_HOME").is_some() {
        return Ok(());
    }
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|_| "无法初始化 Windows 通知")?;
    let result = (|| {
        register_notification_app()?;
        let document = XmlDocument::new().map_err(|_| "无法创建通知")?;
        let xml = format!("<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>", xml_text(title), xml_text(body));
        document
            .LoadXml(&HSTRING::from(xml))
            .map_err(|_| "无法创建通知")?;
        let toast =
            ToastNotification::CreateToastNotification(&document).map_err(|_| "无法创建通知")?;
        if let Some(app) = app {
            use tauri::Manager;
            use windows::{core::IInspectable, Foundation::TypedEventHandler};
            toast
                .Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
                    move |_, _| {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                        Ok(())
                    },
                ))
                .map_err(|_| "无法注册通知点击事件")?;
        }
        toast
            .SetTag(&HSTRING::from("approval"))
            .map_err(|_| "无法创建通知")?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))
            .and_then(|notifier| notifier.Show(&toast))
            .map_err(|_| "Windows 通知不可用")?;
        static RECENT: std::sync::OnceLock<std::sync::Mutex<Vec<ToastNotification>>> =
            std::sync::OnceLock::new();
        if let Ok(mut recent) = RECENT.get_or_init(Default::default).lock() {
            recent.push(toast);
            if recent.len() > 16 {
                recent.remove(0);
            }
        }
        Ok(())
    })();
    unsafe {
        RoUninitialize();
    }
    result
}

#[cfg(not(windows))]
pub fn notify_open(_app: tauri::AppHandle, _title: &str, _body: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn notification_app_id_value(
) -> Result<windows::Win32::System::Com::StructuredStorage::PROPVARIANT, String> {
    use windows::{
        core::PCWSTR,
        Win32::{
            System::{
                Com::StructuredStorage::{
                    PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0,
                },
                Variant::VT_LPWSTR,
            },
            UI::Shell::SHStrDupW,
        },
    };
    let text = wide(APP_ID)?;
    // PROPVARIANT::drop calls PropVariantClear. Give it an owned COM allocation,
    // never a pointer into a Rust Vec that would be freed by two different owners.
    let owned =
        unsafe { SHStrDupW(PCWSTR(text.as_ptr())) }.map_err(|_| "无法创建通知身份".to_owned())?;
    Ok(PROPVARIANT {
        Anonymous: PROPVARIANT_0 {
            Anonymous: std::mem::ManuallyDrop::new(PROPVARIANT_0_0 {
                vt: VT_LPWSTR,
                Anonymous: PROPVARIANT_0_0_0 { pwszVal: owned },
                ..Default::default()
            }),
        },
    })
}

#[cfg(windows)]
fn register_notification_app() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::{w, Interface, PCWSTR},
        Win32::{
            Storage::EnhancedStorage::PKEY_AppUserModel_ID,
            System::{
                Com::{CoCreateInstance, CoTaskMemFree, IPersistFile, CLSCTX_INPROC_SERVER},
                Registry::*,
            },
            UI::Shell::{
                FOLDERID_Programs, IShellLinkW, PropertiesSystem::IPropertyStore,
                SHGetKnownFolderPath, SetCurrentProcessExplicitAppUserModelID, ShellLink,
                KF_FLAG_CREATE,
            },
        },
    };
    // Registration uses pman's own AUMID and a valid current-user Start Menu link.
    // https://learn.microsoft.com/windows/win32/shell/enable-desktop-toast-with-appusermodelid
    let app_id = wide(APP_ID)?;
    let executable = std::env::current_exe().map_err(|_| "无法定位 pman 程序")?;
    let executable_wide: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        SetCurrentProcessExplicitAppUserModelID(PCWSTR(app_id.as_ptr()))
            .map_err(|_| "无法注册 pman 通知身份")?;
        let location = SHGetKnownFolderPath(&FOLDERID_Programs, KF_FLAG_CREATE, None)
            .map_err(|_| "无法定位开始菜单")?;
        let directory = location.to_string();
        CoTaskMemFree(Some(location.as_ptr().cast()));
        let shortcut =
            PathBuf::from(directory.map_err(|_| "开始菜单路径无效")?).join("pman Vault.lnk");
        let shortcut_wide: Vec<u16> = shortcut.as_os_str().encode_wide().chain(Some(0)).collect();
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|_| "无法注册通知快捷方式")?;
        link.SetPath(PCWSTR(executable_wide.as_ptr()))
            .map_err(|_| "无法注册通知快捷方式")?;
        link.SetDescription(w!("pman 本地凭据与 AI 授权工作台"))
            .map_err(|_| "无法注册通知快捷方式")?;
        let properties: IPropertyStore = link.cast().map_err(|_| "无法注册通知快捷方式")?;
        let value = notification_app_id_value()?;
        properties
            .SetValue(&PKEY_AppUserModel_ID, &value)
            .and_then(|_| properties.Commit())
            .map_err(|_| "无法注册通知快捷方式")?;
        let persistent: IPersistFile = link.cast().map_err(|_| "无法注册通知快捷方式")?;
        persistent
            .Save(PCWSTR(shortcut_wide.as_ptr()), true)
            .map_err(|_| "无法保存通知快捷方式")?;
        let registry_path = wide(&format!("Software\\Classes\\AppUserModelId\\{APP_ID}"))?;
        let mut key = HKEY::default();
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(registry_path.as_ptr()),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
        .ok()
        .map_err(|_| "无法注册 pman 通知名称")?;
        let name = wide("pman Vault")?;
        let name_bytes = std::slice::from_raw_parts(name.as_ptr().cast::<u8>(), name.len() * 2);
        let written =
            RegSetValueExW(key, w!("DisplayName"), Some(0), REG_SZ, Some(name_bytes)).ok();
        let _ = RegCloseKey(key);
        written.map_err(|_| "无法保存 pman 通知名称")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn notification_identity_roundtrips_and_drops_without_corrupting_heap() {
        use windows::{
            core::Interface,
            Win32::{
                Storage::EnhancedStorage::PKEY_AppUserModel_ID,
                System::{
                    Com::{CoCreateInstance, CLSCTX_INPROC_SERVER},
                    Variant::VT_LPWSTR,
                    WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
                },
                UI::Shell::{IShellLinkW, PropertiesSystem::IPropertyStore, ShellLink},
            },
        };
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED).unwrap();
            for _ in 0..256 {
                let link: IShellLinkW =
                    CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).unwrap();
                let properties: IPropertyStore = link.cast().unwrap();
                let value = notification_app_id_value().unwrap();
                assert_eq!(value.vt(), VT_LPWSTR);
                properties.SetValue(&PKEY_AppUserModel_ID, &value).unwrap();
                properties.Commit().unwrap();
                drop(value);
                let copied = properties.GetValue(&PKEY_AppUserModel_ID).unwrap();
                assert_eq!(
                    copied
                        .Anonymous
                        .Anonymous
                        .Anonymous
                        .pwszVal
                        .to_string()
                        .unwrap(),
                    APP_ID
                );
            }
            RoUninitialize();
        }
    }
    #[test]
    fn toast_text_cannot_inject_xml_or_controls() {
        assert_eq!(
            xml_text("<text a=\"b\">x&y</text>\0"),
            "&lt;text a=&quot;b&quot;&gt;x&amp;y&lt;/text&gt;"
        );
    }
    #[test]
    fn external_opener_rejects_executable_and_credential_urls() {
        for url in [
            "file:///C:/Windows/system32/calc.exe",
            "cmd:evil",
            "https://user:password@example.com/",
        ] {
            assert!(open_external_url(url).is_err());
        }
    }
}
