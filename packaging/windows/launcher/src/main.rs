#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
const DATA_DIRECTORY_ENV: &str = "SHOWNET_DATA_DIR";

struct PortableLayout {
    application: PathBuf,
    application_directory: PathBuf,
    data_directory: PathBuf,
}

fn portable_layout(launcher: &Path) -> Result<PortableLayout, String> {
    let root = launcher
        .parent()
        .ok_or_else(|| "Portable launcher has no parent directory".to_string())?;
    let application_directory = root.join("App").join("ShowNet");
    Ok(PortableLayout {
        application: application_directory.join("ShowNet.exe"),
        application_directory,
        data_directory: root.join("Data").join("ShowNet"),
    })
}

#[cfg(target_os = "windows")]
fn launch() -> Result<i32, String> {
    let launcher = std::env::current_exe()
        .map_err(|error| format!("Unable to locate ShowNetPortable.exe: {error}"))?;
    let layout = portable_layout(&launcher)?;
    if !layout.application.is_file() {
        return Err(format!(
            "ShowNet application is missing:\n{}",
            layout.application.display()
        ));
    }
    std::fs::create_dir_all(&layout.data_directory)
        .map_err(|error| format!("Unable to create portable data directory: {error}"))?;

    let status = std::process::Command::new(&layout.application)
        .args(std::env::args_os().skip(1))
        .current_dir(&layout.application_directory)
        .env(DATA_DIRECTORY_ENV, &layout.data_directory)
        .status()
        .map_err(|error| format!("Unable to start ShowNet: {error}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(target_os = "windows")]
fn show_error(message: &str) {
    const MB_ICONERROR: u32 = 0x0000_0010;
    const MB_OK: u32 = 0x0000_0000;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(
            window: *mut core::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            kind: u32,
        ) -> i32;
    }

    let text = message.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let caption = "ShowNet Portable"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(target_os = "windows")]
fn main() {
    match launch() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            show_error(&error);
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("ShowNet Portable launcher can only run on Windows.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_application_and_data_under_the_portable_root() {
        let layout =
            portable_layout(Path::new("/Portable/ShowNetPortable/ShowNetPortable.exe")).unwrap();
        assert_eq!(
            layout.application,
            Path::new("/Portable/ShowNetPortable/App/ShowNet/ShowNet.exe")
        );
        assert_eq!(
            layout.application_directory,
            Path::new("/Portable/ShowNetPortable/App/ShowNet")
        );
        assert_eq!(
            layout.data_directory,
            Path::new("/Portable/ShowNetPortable/Data/ShowNet")
        );
    }
}
