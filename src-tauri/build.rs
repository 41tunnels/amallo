fn main() {
    // Must run before tauri_build::build(), which validates that
    // tauri.windows.conf.json's declared resource paths already exist.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        copy_webview2_loader();
    }

    tauri_build::build();
}

// tauri.windows.conf.json bundles `target/<profile>/WebView2Loader.dll` as a
// fixed-path resource, but webview2-com-sys's own build script only ever
// copies the DLL into *its* build-script OUT_DIR (a path hashed per build,
// which Cargo doesn't expose to us — webview2-com-sys declares no `links`
// key, so there's no DEP_*_LOADER env var to read). Nothing else puts a copy
// at the flat path tauri.windows.conf.json expects, so find webview2-com-sys's
// OUT_DIR ourselves among our build-script siblings and copy it over.
fn copy_webview2_loader() {
    use std::{env, fs, path::PathBuf};

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "x86",
        other => panic!("unsupported Windows arch for WebView2Loader.dll: {other}"),
    };

    // OUT_DIR is target/<profile>/build/amallo-<hash>/out (possibly with a
    // target-triple directory ahead of <profile> when cross-compiling) —
    // three levels up is always target/<profile>, where the exe lands.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR should be nested three levels under target/<profile>")
        .to_path_buf();

    let build_dir = profile_dir.join("build");
    let loader = fs::read_dir(&build_dir)
        .unwrap_or_else(|e| panic!("read {build_dir:?}: {e}"))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("out").join(arch).join("WebView2Loader.dll"))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!("WebView2Loader.dll not found under any build script output in {build_dir:?}")
        });

    println!("cargo:rerun-if-changed={}", loader.display());
    fs::copy(&loader, profile_dir.join("WebView2Loader.dll"))
        .unwrap_or_else(|e| panic!("copy {loader:?} to {profile_dir:?}: {e}"));
}
