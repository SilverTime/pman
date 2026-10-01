fn main() {
    // We embed one manifest for every target (bin, lib, tests) ourselves so
    // the lib test harness also resolves comctl32 v6 imports (TaskDialog) —
    // tauri-build's own manifest is only linked into bin targets.
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let icon = manifest_dir.join("icons").join("icon.ico");
    let attrs = tauri_build::Attributes::new()
        .windows_attributes(
            tauri_build::WindowsAttributes::new_without_app_manifest().window_icon_path(&icon),
        );
    tauri_build::try_build(attrs).expect("failed to run tauri-build");
    let manifest = manifest_dir.join("app.manifest");
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
}
