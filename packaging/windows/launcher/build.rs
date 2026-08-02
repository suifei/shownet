use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let icon = manifest_dir.join("../../../src-tauri/icons/icon.ico");
    println!("cargo:rerun-if-changed={}", icon.display());

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let resource = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("launcher.rc");
    let icon_path = icon.to_string_lossy().replace('\\', "/");
    fs::write(&resource, format!("1 ICON \"{icon_path}\"\n")).unwrap();
    embed_resource::compile(resource, embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
