mod backend;
mod client_config;
#[cfg(test)]
mod installation_tests;
mod legacy_http;
mod lifecycle;
mod login;
mod native_dialogs;
mod oauth_login;
mod platform;
mod service;
#[cfg(test)]
mod service_tests;
mod single_instance;
mod storage;

use service::Shared;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::{Emitter, Manager};

pub fn run() {
    let _instance_guard = match single_instance::acquire() {
        Ok(Some(guard)) => guard,
        Ok(None) => return,
        Err(error) => {
            eprintln!("{error}");
            return;
        }
    };
    let shared = Shared::open().expect("Unable to open the pman workspace");
    let startup = shared.clone();
    let exit_requested = Arc::new(AtomicBool::new(false));
    let exit_state = exit_requested.clone();
    tauri::Builder::default()
        .manage(shared)
        .manage(exit_requested)
        .invoke_handler(tauri::generate_handler![
            backend::vault_status,
            backend::vault_create,
            backend::vault_unlock,
            backend::vault_lock,
            backend::management_lock,
            backend::management_unlock,
            backend::management_unlock_hello,
            backend::service_pause,
            backend::service_resume,
            backend::settings_get,
            backend::settings_update,
            backend::window_hide,
            backend::application_exit,
            backend::list_sites,
            backend::connection_status,
            backend::connection_check,
            backend::site_add,
            backend::site_update_metadata,
            backend::site_rotate,
            backend::site_remove,
            backend::site_reveal,
            backend::site_copy,
            backend::generate_password,
            backend::list_harnesses,
            backend::ensure_harness,
            backend::delete_harness,
            backend::set_harness_policy,
            backend::add_harness_allow_rule,
            backend::remove_harness_allow_rule,
            backend::grant_add,
            backend::grant_connection,
            backend::list_approvals,
            backend::assistance_list,
            backend::assistance_decide,
            backend::decide_approval,
            backend::list_audit,
            backend::broker_call,
            backend::clients_list,
            backend::client_pair,
            backend::client_revoke,
            backend::client_config_preview,
            backend::client_config_apply,
            backend::client_config_restore,
            backend::client_test,
            storage::vault_backup,
            storage::vault_import,
            storage::vault_migrate_legacy,
            login::open_login_window,
            login::login_capture_cookies,
            login::close_login_window,
            login::e10_begin,
            login::e10_complete,
            login::e10_cancel,
            login::e10_check,
            oauth_login::oauth_begin,
            oauth_login::oauth_complete,
            oauth_login::oauth_cancel,
            oauth_login::oauth_status,
            oauth_login::oauth_refresh
        ])
        .setup(move |app| {
            use tauri::{
                menu::{Menu, MenuItem},
                tray::TrayIconBuilder,
            };
            startup.start_background(app.handle().clone());
            let show = MenuItem::with_id(app, "show", "打开 pman", true, None::<&str>)?;
            let hide = MenuItem::with_id(app, "hide", "隐藏窗口", true, None::<&str>)?;
            let lock = MenuItem::with_id(app, "lock-ui", "锁定管理界面", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "暂停 AI 服务", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出并停止服务", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &hide, &lock, &pause, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .tooltip("pman · 本地 AI 授权工作台")
                .menu(&menu)
                .show_menu_on_left_click(true);
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.on_menu_event(move |app, event| {
                let shared = app.state::<Shared>();
                match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "lock-ui" => {
                        shared.lock_interface();
                        service::close_login_windows(app);
                        let _ = app.emit("management-locked", ());
                    }
                    "pause" => {
                        if shared.pause().is_ok() {
                            service::close_login_windows(app);
                            let _ = app.emit("management-locked", ());
                            let _ = app.emit("service-changed", ());
                        }
                    }
                    "quit" => {
                        if shared.pause().is_ok() {
                            app.state::<Arc<AtomicBool>>().store(true, Ordering::SeqCst);
                            app.exit(0);
                        }
                    }
                    _ => {}
                }
            })
            .build(app)?;
            if let Some(window) = app.get_webview_window("main") {
                let session = app.handle().clone();
                let _ = platform::watch_session(&window, move || {
                    session.state::<Shared>().lock_interface();
                    service::close_login_windows(&session);
                    let _ = session.emit("management-locked", ());
                });
                if std::env::args().any(|a| a == "--background") {
                    let _ = window.hide();
                }
            }
            single_instance::attach(app.handle().clone()).map_err(std::io::Error::other)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("Unable to start pman desktop")
        .run(move |_app, event| {
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() && !exit_state.load(Ordering::SeqCst) {
                    api.prevent_exit();
                }
            }
        });
}
